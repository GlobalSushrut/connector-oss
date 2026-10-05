//! DisclosureGrant store — S0–S5 ceilings; quarantine voids live grants.

use connector_trust::{DisclosureGrant, DisclosureLevel, DISCLOSURE_GRANT_SCHEMA};
use sha2::{Digest, Sha256};

use crate::state::SharedState;

use super::{broker_epoch, now_ms, store, svf_enabled};

pub const GRANT_FOLDER: &str = "svf_disclosure_grants";

pub fn put_grant(state: &SharedState, grant: &DisclosureGrant) -> Result<(), String> {
    let key = format!("{}:{}", grant.agent_vid, grant.grant_id);
    let v = serde_json::to_value(grant).map_err(|e| e.to_string())?;
    store::put_json(state, GRANT_FOLDER, &key, &v);
    Ok(())
}

pub fn list_grants(state: &SharedState, agent_vid: &str) -> Vec<DisclosureGrant> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(keys) = es.folder_keys(GRANT_FOLDER, Some(agent_vid)) else {
        return Vec::new();
    };
    let now = now_ms();
    keys.into_iter()
        .filter_map(|k| es.folder_get(GRANT_FOLDER, &k).ok().flatten())
        .filter_map(|v| serde_json::from_value::<DisclosureGrant>(v).ok())
        .filter(|g| {
            g.expires_at_ms
                .map(|exp| exp == 0 || exp > now)
                .unwrap_or(true)
        })
        .collect()
}

/// Highest grant ceiling for an object (or agent-wide `*`) that covers `purpose`.
pub fn max_granted_level(
    state: &SharedState,
    agent_vid: &str,
    object_id: &str,
    purpose: &str,
) -> DisclosureLevel {
    let mut max = DisclosureLevel::S0Stub;
    for g in list_grants(state, agent_vid) {
        if g.object_id != object_id && g.object_id != "*" {
            continue;
        }
        if !g.purpose.is_empty()
            && g.purpose != "*"
            && !purpose.is_empty()
            && !purpose.contains(&g.purpose)
            && !g.purpose.contains(purpose)
        {
            continue;
        }
        if g.max_level.rank() > max.rank() {
            max = g.max_level;
        }
    }
    // Default Talk ceiling without grants: S1
    if max == DisclosureLevel::S0Stub && svf_enabled() {
        DisclosureLevel::S1Labels
    } else {
        max
    }
}

pub fn mint_grant(
    state: &SharedState,
    agent_vid: &str,
    object_id: &str,
    max_level: DisclosureLevel,
    purpose: &str,
    ttl_ms: Option<i64>,
) -> DisclosureGrant {
    let epoch = broker_epoch(state, agent_vid);
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{agent_vid}:{object_id}:{}:{purpose}:{epoch}", max_level.as_str()).as_bytes())
    );
    let grant = DisclosureGrant {
        schema: DISCLOSURE_GRANT_SCHEMA.to_string(),
        grant_id: format!("dg-{}", &digest[..16.min(digest.len())]),
        object_id: object_id.to_string(),
        max_level,
        purpose: if purpose.is_empty() {
            "*".into()
        } else {
            purpose.to_string()
        },
        agent_vid: agent_vid.to_string(),
        expires_at_ms: ttl_ms.map(|t| now_ms() + t),
        broker_epoch: epoch,
    };
    let _ = put_grant(state, &grant);
    grant
}

/// Quarantine: freeze CDP and drop grant usefulness by epoch mismatch (maps voided).
pub fn grants_frozen(state: &SharedState, agent_vid: &str) -> bool {
    crate::substrate::llm_sealed_context::agent_brain_quarantined(state, agent_vid)
}
