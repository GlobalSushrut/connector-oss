//! RESOLVE — private topology / credential binding lookup (does not mint leases).

use connector_trust::{
    ResolveRequest, ResolveResult, RESOLVE_REQUEST_SCHEMA, RESOLVE_RESULT_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::SharedState;

use super::{broker_epoch, grants, store, svf_enabled};

/// Parse `{{obj:type.id}}` or bare object_id / dual-format handle string.
pub fn parse_object_id(handle: &str) -> String {
    let h = handle.trim();
    if let Some(inner) = h.strip_prefix("{{obj:") {
        if let Some(end) = inner.find("}}") {
            return inner[..end].trim().to_string();
        }
    }
    if let Some(first) = h.split_whitespace().next() {
        if first.starts_with("{{obj:") {
            return parse_object_id(first);
        }
    }
    h.to_string()
}

/// Resolve a semantic handle to private binding metadata + WorldGrant pore (lookup only).
pub fn resolve(state: &SharedState, req: &ResolveRequest) -> ResolveResult {
    if !svf_enabled() {
        return ResolveResult {
            schema: RESOLVE_RESULT_SCHEMA.to_string(),
            handle: req.handle.clone(),
            resolved: false,
            private_binding_digest: None,
            world_grant_pore: None,
            denial_reason: Some("svf_disabled".into()),
        };
    }
    if grants::grants_frozen(state, &req.agent_vid) {
        return ResolveResult {
            schema: RESOLVE_RESULT_SCHEMA.to_string(),
            handle: req.handle.clone(),
            resolved: false,
            private_binding_digest: None,
            world_grant_pore: None,
            denial_reason: Some("quarantine_freezes_cdp".into()),
        };
    }

    let object_id = parse_object_id(&req.handle);
    let obj = match store::get_object(state, &req.agent_vid, &object_id) {
        Some(o) => o,
        None => {
            let _ = super::semanticize::semanticize_agent(state, &req.agent_vid);
            match store::get_object(state, &req.agent_vid, &object_id) {
                Some(o) => o,
                None => {
                    return ResolveResult {
                        schema: RESOLVE_RESULT_SCHEMA.to_string(),
                        handle: req.handle.clone(),
                        resolved: false,
                        private_binding_digest: None,
                        world_grant_pore: None,
                        denial_reason: Some(format!("object_not_found:{object_id}")),
                    };
                }
            }
        }
    };

    if req.broker_epoch != 0 && req.broker_epoch != broker_epoch(state, &req.agent_vid) {
        return ResolveResult {
            schema: RESOLVE_RESULT_SCHEMA.to_string(),
            handle: req.handle.clone(),
            resolved: false,
            private_binding_digest: None,
            world_grant_pore: None,
            denial_reason: Some("epoch_mismatch".into()),
        };
    }

    let binding_src = format!(
        "{}|{}|{}|{:?}|{:?}",
        obj.agent_vid, obj.object_id, obj.object_type, obj.mem_packet_cid, obj.knot_node_id
    );
    let private_binding_digest = format!("{:x}", Sha256::digest(binding_src.as_bytes()));

    let pore = format!("mcp_tool:{}", obj.object_type);
    let pore_ok = crate::kernel::world_gateway::assert_grant_allows(
        state.as_ref(),
        &req.agent_vid,
        &pore,
        "tool.dispatch",
    )
    .is_ok();
    let pore_alt = obj.object_id.clone();
    let pore_alt_ok = crate::kernel::world_gateway::assert_grant_allows(
        state.as_ref(),
        &req.agent_vid,
        &pore_alt,
        "tool.dispatch",
    )
    .is_ok();

    let world_grant_pore = if pore_ok {
        Some(pore)
    } else if pore_alt_ok {
        Some(pore_alt)
    } else {
        None
    };

    ResolveResult {
        schema: RESOLVE_RESULT_SCHEMA.to_string(),
        handle: req.handle.clone(),
        resolved: true,
        private_binding_digest: Some(private_binding_digest),
        world_grant_pore,
        denial_reason: None,
    }
}

pub fn resolve_json(state: &SharedState, agent_vid: &str, handle: &str, purpose: &str) -> Value {
    let req = ResolveRequest {
        schema: RESOLVE_REQUEST_SCHEMA.to_string(),
        handle: handle.to_string(),
        agent_vid: agent_vid.to_string(),
        purpose: purpose.to_string(),
        broker_epoch: broker_epoch(state, agent_vid),
    };
    json!(resolve(state, &req))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_obj_handle() {
        assert_eq!(parse_object_id("{{obj:email.inbox-1}}"), "email.inbox-1");
        assert_eq!(
            parse_object_id("{{obj:email.inbox-1}} ⟦conn:obj:deadbeef⟧"),
            "email.inbox-1"
        );
        assert_eq!(parse_object_id("bare.id"), "bare.id");
    }
}
