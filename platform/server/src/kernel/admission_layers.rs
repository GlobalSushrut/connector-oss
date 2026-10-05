//! Three admission layers — supreme membrane. Bypass is not a product path.
//!
//! 1. **Root HITL** — human is root. Every action waits for a human. Kernel root
//!    passcode is required to *change* layer assignments (not an agent secret).
//! 2. **Cone (augmented)** — AI may *suggest*; a human must approve the exact
//!    action digest before the agent may act. Default for world access.
//! 3. **App** — automation. Agent may act without per-action HITL **only** for
//!    capabilities the owner justified on this (agent × address) grant.
//!
//! Fold rule (never invert): Block > Ask (root/cone) > App Allow.
//! Charter deny, missing grant, and unknown caps stay Block.
//! Cone/root **upgrade** charter Allow → Ask. App Allow **cannot** downgrade Ask/Block.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::kernel::world_gateway;
use crate::state::PlatformState;

pub const LAYERS_SCHEMA: &str = "connector.admission.layers.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionLayer {
    /// Human is root — always Ask (except ambient e-stop).
    Root,
    /// AI suggests, human approves (Ask). Default.
    Cone,
    /// Justified automation Allow for listed caps only.
    App,
}

impl AdmissionLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Cone => "cone",
            Self::App => "app",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "root" | "hitl" | "human" => Self::Root,
            "app" | "allow" | "automation" => Self::App,
            _ => Self::Cone,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorldAdmit {
    /// No grants yet — charter/HITL policy only (lab). Harden CONP → Cone.
    LegacyCharter,
    Layer(AdmissionLayer),
}

pub fn catalog() -> Value {
    json!({
        "schema": LAYERS_SCHEMA,
        "supreme": true,
        "bypass": "impossible — every Talk/tool/CONP path is admit_* ; App Allow cannot skip charter/grant/trace; Cone/root cannot execute without digest HITL consume",
        "layers": [
            {
                "id": "root",
                "rank": 1,
                "who": "human",
                "ai": "may draft, never execute",
                "execute": "only after human HITL on this action digest",
            },
            {
                "id": "cone",
                "rank": 2,
                "who": "human + AI",
                "ai": "suggests",
                "execute": "only after human approves the suggestion (Ask)",
            },
            {
                "id": "app",
                "rank": 3,
                "who": "automation",
                "ai": "may act without per-action HITL",
                "execute": "only for (agent × address × cap) a **human** justified with kernel root — agents cannot mint this power. Still Block if charter/grant deny",
            }
        ],
        "fold": "Block > cone/root Ask > app Allow. App never downgrades Ask or Block.",
        "per_cell": "Agent A at address P is independent of A at Q and of B at P. Caps can split: some app, some cone, on the same grant.",
    })
}

fn cap_match(listed: &[Value], cap: &str) -> bool {
    let cap = cap.trim().to_ascii_lowercase();
    if cap.is_empty() {
        return false;
    }
    listed.iter().any(|c| {
        c.as_str()
            .map(|s| {
                let s = s.trim().to_ascii_lowercase();
                s == cap || s == "*" || cap.starts_with(&s) || s.starts_with(&cap)
            })
            .unwrap_or(false)
    })
}

/// Resolve layer for this (agent × address × capability). Err = Block (no execute).
pub fn admit_world(
    state: &PlatformState,
    agent_pid: &str,
    entity_id: &str,
    capability: &str,
) -> Result<WorldAdmit, String> {
    let grants = world_gateway::list_grants(state, Some(agent_pid));
    if grants.is_empty() {
        return admit_empty_grants(entity_id);
    }
    let want = entity_id.trim().to_ascii_lowercase();
    if want.is_empty() {
        return Err("world_address_required".into());
    }
    for g in &grants {
        let addr = g
            .get("address")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if addr.is_empty() {
            continue;
        }
        let addr_ok = want == addr || want.starts_with(&addr) || addr.starts_with(&want);
        if !addr_ok {
            continue;
        }
        let effect = g
            .get("effect")
            .and_then(|x| x.as_str())
            .unwrap_or("ask")
            .to_ascii_lowercase();
        if effect == "block" {
            return Err(format!(
                "world_grant_blocked: agent={agent_pid} address={entity_id}"
            ));
        }
        let access = g
            .get("access")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        if !access.is_empty() && !cap_match(&access, capability) {
            return Err(format!(
                "world_grant_capability_denied: agent={agent_pid} address={entity_id} cap={capability}"
            ));
        }
        let layer = AdmissionLayer::parse(
            g.get("layer")
                .and_then(|x| x.as_str())
                .unwrap_or("cone"),
        );
        let app_allow = g
            .get("app_allow")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let cone_ask = g
            .get("cone_ask")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        if cap_match(&cone_ask, capability) || layer == AdmissionLayer::Root {
            return Ok(WorldAdmit::Layer(if layer == AdmissionLayer::Root {
                AdmissionLayer::Root
            } else {
                AdmissionLayer::Cone
            }));
        }
        if cap_match(&app_allow, capability) {
            let just = g
                .get("justification")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim();
            if just.len() < 16 {
                return Ok(WorldAdmit::Layer(AdmissionLayer::Cone));
            }
            return Ok(WorldAdmit::Layer(AdmissionLayer::App));
        }
        return Ok(WorldAdmit::Layer(match layer {
            AdmissionLayer::App => {
                let just = g
                    .get("justification")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .trim();
                if just.len() < 16 || !app_allow.is_empty() {
                    AdmissionLayer::Cone
                } else {
                    AdmissionLayer::App
                }
            }
            AdmissionLayer::Root => AdmissionLayer::Root,
            AdmissionLayer::Cone => AdmissionLayer::Cone,
        }));
    }
    Err(format!(
        "world_grant_missing: agent={agent_pid} has grants but none for address={entity_id} — owner must fill gateway form"
    ))
}

pub fn world_entity_from_params(parameters: &Value) -> Option<String> {
    for k in ["entity_id", "address", "url", "target", "endpoint"] {
        if let Some(s) = parameters.get(k).and_then(|x| x.as_str()) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn world_grants_fail_closed() -> bool {
    if std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
    {
        // Playground: pilots would otherwise deny every tool:* with no demo grants.
        return std::env::var("CONNECTOR_WORLD_GRANTS_FAIL_CLOSED")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
    }
    crate::kernel::agent_principal::intelligence_hardening_on()
        || crate::connector_profile::is_productionish_env()
}

/// Named world addresses (URLs, hosts, entity ids) require an owner grant when fail-closed.
pub(crate) fn world_address_requires_grant(entity_id: &str) -> bool {
    let t = entity_id.trim();
    if t.is_empty() {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    lower.contains("://")
        || lower.starts_with("www.")
        || lower.contains('.')
        || lower.contains(':')
        || lower == "localhost"
        || lower.starts_with("local:")
        || lower.starts_with("file:")
        || lower.starts_with("tool:")
        || lower.starts_with("host_proc:")
        || lower.starts_with("machine:")
        || lower.starts_with("device:")
        || lower.starts_with("robot:")
        || lower.starts_with("iot:")
        || lower.starts_with("mqtt:")
        || lower.starts_with("mcp:")
}

pub(crate) fn admit_empty_grants(entity_id: &str) -> Result<WorldAdmit, String> {
    let want = entity_id.trim();
    if world_grants_fail_closed() && world_address_requires_grant(want) {
        return Err(format!(
            "world_grant_required: address={entity_id} — owner must grant this agent before world egress"
        ));
    }
    if crate::kernel::agent_principal::intelligence_hardening_on() {
        return Ok(WorldAdmit::Layer(AdmissionLayer::Cone));
    }
    Ok(WorldAdmit::LegacyCharter)
}

pub fn validate_grant_layers(
    layer: &str,
    effect: &str,
    app_allow: &[String],
    justification: Option<&str>,
) -> Result<(), String> {
    let layer = AdmissionLayer::parse(layer);
    let effect = effect.trim().to_ascii_lowercase();
    let just = justification.unwrap_or("").trim();
    let needs_app = layer == AdmissionLayer::App
        || effect == "allow"
        || !app_allow.is_empty();
    if needs_app && just.len() < 16 {
        return Err(
            "app_layer_requires_justification (min 16 chars: why agent A may act without HITL at address P)"
                .into(),
        );
    }
    if effect == "allow" && layer == AdmissionLayer::Root {
        return Err("root_layer_cannot_be_allow — human is root, actions Ask until approved".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn justification_required_for_app() {
        assert!(validate_grant_layers("app", "allow", &["x".into()], Some("too short")).is_err());
        assert!(validate_grant_layers(
            "app",
            "allow",
            &["x".into()],
            Some("sensor read-only telemetry for bay 3 line")
        )
        .is_ok());
        assert!(validate_grant_layers("cone", "ask", &[], None).is_ok());
        assert!(validate_grant_layers("root", "allow", &[], Some("xxxxxxxxxxxxxxxx")).is_err());
    }

    #[test]
    fn parse_layers() {
        assert_eq!(AdmissionLayer::parse("hitl"), AdmissionLayer::Root);
        assert_eq!(AdmissionLayer::parse("cone"), AdmissionLayer::Cone);
        assert_eq!(AdmissionLayer::parse("automation"), AdmissionLayer::App);
    }

    #[test]
    fn world_urls_require_grant() {
        assert!(world_address_requires_grant("https://api.example.com/v1"));
        assert!(world_address_requires_grant("mqtt://broker:1883"));
        assert!(world_address_requires_grant("10.0.0.5:443"));
        assert!(world_address_requires_grant("local:host"));
        assert!(world_address_requires_grant("localhost"));
        assert!(world_address_requires_grant("tool:mcp/search"));
        assert!(world_address_requires_grant("file:/etc/passwd"));
        assert!(!world_address_requires_grant(""));
        assert!(!world_address_requires_grant("memory"));
    }

    #[test]
    fn empty_grants_fail_closed_for_urls() {
        // Direct helper: production-like path is env-dependent, so assert the
        // address classifier that gates the fail-closed branch.
        assert!(world_address_requires_grant("https://evil.example"));
    }
}
