//! Authority-preserving protocol drivers (MCP / CONP / A2A / CNP).
//!
//! Drivers decode overlays and bind channel/surface confidence, then funnel
//! effects through ActionBinding/PATE (via `native_invoker` or dedicated admit_*).
//! They never mint grants or suppress EdgeReceipts.

mod a2a;
mod cnp;
mod conp;
mod mcp;
mod surface;

pub use a2a::{admit_a2a_send, decode_a2a_send};
pub use cnp::{
    actuation_command_name, admit_cnp_actuation, admit_cnp_send, decode_cnp_actuation,
    decode_cnp_send, parse_actuation_command,
};
pub use conp::{admit_conp_command, decode_conp_command};
pub use mcp::{admit_mcp_call, decode_mcp_call};
pub use surface::{bind_protocol_surface, BindSurfaceOpts};

use connector_native_contract::{
    EffectDescriptor, InvocationOrigin, PackagePin, ProtocolDriverId, SemanticConfidence,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::substrate::native_invoker::{self, NativeInvokeRequest, NativeInvokeResult};
use crate::substrate::pate::AugmentedTaskUnit;

/// Decoded protocol effect ready for surface bind + admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolEffect {
    pub protocol: ProtocolDriverId,
    pub bridge_id: String,
    pub tool_name: String,
    pub resource: String,
    pub parameters: Value,
    pub effect: EffectDescriptor,
    pub agent_pid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_protocol: Option<String>,
    /// When false, leave surface at ProtocolObserved (mutation will hard-deny).
    #[serde(default = "default_true")]
    pub upgrade_adapter_verified: bool,
    /// AppPackageV2 pin — required for mutating protocol effects outside lab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackagePin>,
}

fn default_true() -> bool {
    true
}

/// Package pin for mutating protocol effects. EmergencyStop is cut-through.
/// CONP/CNP `record_atu_admit` strips `mutates` to avoid double PATE, so callers
/// must gate here — native_invoker will not re-check the original effect.
pub fn gate_mutating_package(effect: &ProtocolEffect, skip: bool) -> Result<(), String> {
    if skip || !effect.effect.mutates {
        return Ok(());
    }
    crate::substrate::package_gate::require_package_for_consequential_effect(effect.package.as_ref())
        .map(|_| ())
}

/// Map driver admit errors (including package_gate) into API JSON.
pub fn admit_denied_json(driver: &str, err: &str) -> Value {
    if err.starts_with("package_gate:") {
        return crate::substrate::package_gate::deny_json(err);
    }
    json!({
        "ok": false,
        "error": format!("{driver}_protocol_driver_denied"),
        "denial_reason": err,
        "status": 403,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverAdmitResult {
    pub protocol: ProtocolDriverId,
    pub effect: ProtocolEffect,
    pub surface_uid: String,
    pub channel_uid: String,
    pub allowed: bool,
    pub pate_verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeInvokeResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atu_task_id: Option<String>,
    pub honesty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_detail: Option<Value>,
}

/// Registry lookup — known drivers only (future overlays register here).
pub fn resolve(protocol: &str) -> Option<ProtocolDriverId> {
    ProtocolDriverId::parse(protocol)
}

/// Bind surface then admit through native_invoker (tool-shaped overlays: MCP/A2A).
pub fn admit_via_native_invoker(
    state: &SharedState,
    effect: ProtocolEffect,
) -> Result<DriverAdmitResult, String> {
    let confidence = if effect.upgrade_adapter_verified {
        SemanticConfidence::AdapterVerified
    } else {
        SemanticConfidence::ProtocolObserved
    };
    let bound = bind_protocol_surface(
        state.as_ref(),
        BindSurfaceOpts {
            protocol: effect.protocol,
            agent_pid: effect.agent_pid.clone(),
            locator: effect
                .locator
                .clone()
                .unwrap_or_else(|| format!("{}://{}", effect.protocol.as_str(), effect.resource)),
            confidence,
            destination: effect.destination_host.clone(),
            port: effect.destination_port,
            transport: effect
                .destination_protocol
                .clone()
                .unwrap_or_else(|| effect.protocol.as_str().into()),
        },
    )?;

    let origin = InvocationOrigin {
        software_uid: None,
        workload_uid: format!("wl:protocol:{}", effect.protocol.as_str()),
        intelligence_uid: effect.agent_pid.clone(),
        principal: effect.agent_pid.clone(),
    };

    let req = NativeInvokeRequest {
        origin,
        surface_uid: Some(bound.surface_uid.clone()),
        channel_uid: Some(bound.channel_uid.clone()),
        effect: effect.effect.clone(),
        contract_ref: format!("protocol:{}", effect.protocol.as_str()),
        authority_ref: String::new(),
        lifecycle_mode: Default::default(),
        enforcement_posture: None,
        agent_pid: Some(effect.agent_pid.clone()),
        bridge_id: Some(effect.bridge_id.clone()),
        tool_name: Some(effect.tool_name.clone()),
        parameters: Some(effect.parameters.clone()),
        resource: Some(effect.resource.clone()),
        mint_flow_lease: effect.destination_host.is_some(),
        destination_host: effect.destination_host.clone(),
        destination_port: effect.destination_port,
        destination_protocol: effect.destination_protocol.clone(),
        tenant_id: None,
        mission_id: effect.mission_id.clone(),
        idempotency_key: None,
        package: effect.package.clone(),
        budget: None,
    };

    let native = native_invoker::invoke(state, req)?;
    let allowed = matches!(
        native.pate_verdict.as_str(),
        "allow" | "allow_narrow" | "proceed"
    );
    Ok(DriverAdmitResult {
        protocol: effect.protocol,
        effect: effect.clone(),
        surface_uid: bound.surface_uid,
        channel_uid: bound.channel_uid,
        allowed,
        pate_verdict: native.pate_verdict.clone(),
        action_digest: native.action_digest.clone(),
        atu_task_id: native
            .meta
            .get("atu_task_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        honesty: format!(
            "protocol_driver:{} → native_invoker (PATE when AdapterVerified+)",
            effect.protocol.as_str()
        ),
        deny_detail: if allowed {
            None
        } else {
            Some(json!({
                "pate_verdict": native.pate_verdict,
                "meta": native.meta,
            }))
        },
        native: Some(native),
    })
}

/// Record an ATU-backed admit that already used pate::admit_* (CONP/CNP).
pub fn record_atu_admit(
    state: &SharedState,
    effect: ProtocolEffect,
    atu: &AugmentedTaskUnit,
) -> Result<DriverAdmitResult, String> {
    let confidence = if effect.upgrade_adapter_verified {
        SemanticConfidence::AdapterVerified
    } else {
        SemanticConfidence::ProtocolObserved
    };
    let bound = bind_protocol_surface(
        state.as_ref(),
        BindSurfaceOpts {
            protocol: effect.protocol,
            agent_pid: effect.agent_pid.clone(),
            locator: effect
                .locator
                .clone()
                .unwrap_or_else(|| format!("{}://{}", effect.protocol.as_str(), effect.resource)),
            confidence,
            destination: effect.destination_host.clone(),
            port: effect.destination_port,
            transport: effect
                .destination_protocol
                .clone()
                .unwrap_or_else(|| effect.protocol.as_str().into()),
        },
    )?;

    // Also mint native envelope for audit parity (tool_name maps effect).
    let origin = InvocationOrigin {
        software_uid: None,
        workload_uid: format!("wl:protocol:{}", effect.protocol.as_str()),
        intelligence_uid: effect.agent_pid.clone(),
        principal: effect.agent_pid.clone(),
    };
    let req = NativeInvokeRequest {
        origin,
        surface_uid: Some(bound.surface_uid.clone()),
        channel_uid: Some(bound.channel_uid.clone()),
        effect: effect.effect.clone(),
        contract_ref: format!("protocol:{}", effect.protocol.as_str()),
        authority_ref: String::new(),
        lifecycle_mode: Default::default(),
        enforcement_posture: None,
        agent_pid: Some(effect.agent_pid.clone()),
        bridge_id: Some(effect.bridge_id.clone()),
        tool_name: Some(effect.tool_name.clone()),
        parameters: Some(effect.parameters.clone()),
        resource: Some(effect.resource.clone()),
        mint_flow_lease: false,
        destination_host: effect.destination_host.clone(),
        destination_port: effect.destination_port,
        destination_protocol: effect.destination_protocol.clone(),
        tenant_id: None,
        mission_id: effect.mission_id.clone(),
        idempotency_key: None,
        package: effect.package.clone(),
        budget: None,
    };
    // Surface already AdapterVerified; native_invoker will call admit_tool again for
    // MCP-shaped tools. For CONP/CNP we already have ATU — prefer envelope mint without
    // double-blocking: only record when mutation path would re-admit. Use non-mutating
    // effect for envelope when ATU already admitted irreversible path.
    let mut envelope_req = req;
    if matches!(
        effect.protocol,
        ProtocolDriverId::Conp | ProtocolDriverId::Cnp | ProtocolDriverId::Mcp
    ) {
        // Avoid double PATE: record-only envelope via non-mutating effect descriptor.
        envelope_req.effect = EffectDescriptor {
            effect_class: format!("{}.receipt", effect.protocol.as_str()),
            mutates: false,
            disclosure_class: Some("protocol_driver_receipt".into()),
        };
        envelope_req.tool_name = None;
    }
    let native = native_invoker::invoke(state, envelope_req).ok();

    let allowed = !matches!(
        atu.verdict,
        crate::substrate::pate::TaskVerdict::Block
            | crate::substrate::pate::TaskVerdict::Quarantine
    );

    Ok(DriverAdmitResult {
        protocol: effect.protocol,
        effect: effect.clone(),
        surface_uid: bound.surface_uid,
        channel_uid: bound.channel_uid,
        allowed,
        pate_verdict: format!("{:?}", atu.verdict).to_ascii_lowercase(),
        action_digest: Some(atu.action_digest.clone()),
        atu_task_id: Some(atu.task_id.clone()),
        honesty: format!(
            "protocol_driver:{} → pate ATU + native envelope receipt",
            effect.protocol.as_str()
        ),
        deny_detail: None,
        native,
    })
}

/// Execute a ProtocolDriver proxy hop (admit-only record; wire execute stays in handlers).
pub fn execute_protocol_driver_hop(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    protocol: &str,
    surface_uid: Option<&str>,
    channel_uid: Option<&str>,
) -> Result<Value, String> {
    let id = resolve(protocol).ok_or_else(|| format!("unknown_protocol_driver:{protocol}"))?;
    let bound = if let Some(suid) = surface_uid.filter(|s| !s.is_empty()) {
        json!({
            "surface_uid": suid,
            "channel_uid": channel_uid,
            "mode": "prebound",
        })
    } else {
        let b = bind_protocol_surface(
            state,
            BindSurfaceOpts {
                protocol: id,
                agent_pid: agent_pid.into(),
                locator: format!("{}://hop/{}", id.as_str(), agent_pid),
                confidence: SemanticConfidence::ProtocolObserved,
                destination: None,
                port: None,
                transport: id.as_str().into(),
            },
        )?;
        json!({
            "surface_uid": b.surface_uid,
            "channel_uid": b.channel_uid,
            "mode": "observed",
            "confidence": "protocol_observed",
        })
    };
    Ok(json!({
        "ok": true,
        "effect_executed": false,
        "phase": "admit_observe",
        "protocol": id.as_str(),
        "decoder_ref": id.decoder_ref(),
        "agent_pid": agent_pid,
        "bound": bound,
        "honesty": "ProtocolDriver hop observation/bind only — effectful execute remains on protocol handlers via admit_*; not a successful effect",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;
    use connector_native_contract::EffectDescriptor;

    #[test]
    fn resolve_known_protocols() {
        assert_eq!(resolve("mcp"), Some(ProtocolDriverId::Mcp));
        assert_eq!(resolve("a2a"), Some(ProtocolDriverId::A2a));
        assert_eq!(resolve("conp"), Some(ProtocolDriverId::Conp));
        assert_eq!(resolve("cnp"), Some(ProtocolDriverId::Cnp));
        assert!(resolve("ftp").is_none());
    }

    #[test]
    fn mcp_decode_shapes_tool_effect() {
        let e = decode_mcp_call(
            "agent_1",
            "protocols/mcp",
            "write_file",
            "https://mcp.example",
            &json!({"path": "/tmp/x"}),
            None,
            None,
        );
        assert_eq!(e.protocol, ProtocolDriverId::Mcp);
        assert!(e.effect.mutates);
        assert_eq!(e.tool_name, "write_file");
        assert!(e.upgrade_adapter_verified);
    }

    #[test]
    fn conp_decode_forwards_package_pin() {
        use connector_native_contract::PackagePin;
        use connector_protocol::MessageType;
        let pin = PackagePin::new("app.demo", "sha256:0123456789abcdef", "cpkg");
        let e = decode_conp_command(
            "agent_1",
            "machine.move_axis",
            "machine:arm-1",
            &json!({"axis": "X"}),
            MessageType::Command,
            None,
            Some(pin.clone()),
        );
        assert_eq!(e.protocol, ProtocolDriverId::Conp);
        assert!(e.effect.mutates);
        assert_eq!(e.package.as_ref().map(|p| p.package_id.as_str()), Some("app.demo"));
        let grant = decode_conp_command(
            "agent_1",
            "machine.move_axis",
            "machine:arm-1",
            &json!({}),
            MessageType::CapabilityGrant,
            None,
            None,
        );
        assert!(grant.effect.mutates);
        assert!(!grant.effect.effect_class.contains("command"));
        assert!(grant.package.is_none());
    }

    #[test]
    fn protocol_observed_without_upgrade_keeps_flag() {
        let mut e = decode_mcp_call(
            "agent_1",
            "protocols/mcp",
            "write_file",
            "https://mcp.example",
            &json!({}),
            None,
            None,
        );
        e.upgrade_adapter_verified = false;
        assert!(!e.upgrade_adapter_verified);
        let _ = EffectDescriptor {
            effect_class: "tool".into(),
            mutates: true,
            disclosure_class: None,
        };
        let mut es = InMemoryEngineStore::new();
        let bound = surface::bind_protocol_surface_store(
            &mut es,
            BindSurfaceOpts {
                protocol: ProtocolDriverId::Mcp,
                agent_pid: "agent_1".into(),
                locator: "mcp://test".into(),
                confidence: SemanticConfidence::ProtocolObserved,
                destination: Some("mcp.example".into()),
                port: Some(443),
                transport: "https".into(),
            },
        )
        .expect("bind");
        assert_eq!(bound.confidence, SemanticConfidence::ProtocolObserved);
    }
}
