//! Content-addressed Connector IR (v1).
//!
//! Unifies CCL/CLS compile output with native invocation: typed interfaces,
//! effect rows that require admission, capability imports, and supervision
//! hints. `SolutionContract` remains the executable CLS artifact; this IR is
//! the neutral, digest-bound projection used by packages, workflows and Glue.

use serde::{Deserialize, Serialize};

use crate::digest_hex;

/// Schema identifier for Connector IR payloads.
pub const CONNECTOR_IR_V1_SCHEMA: &str = "connector.ir.v1";

/// Content-addressed Connector IR v1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectorIrV1 {
    pub schema: String,
    /// Digest of the canonical IR body (`cir1-sha256-…`).
    pub ir_cid: String,
    /// Underlying CLS `SolutionContract` CID (`cls1-sha256-…`) when compiled from CCL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solution_contract_cid: Option<String>,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default)]
    pub interfaces: Vec<IrInterfaceDecl>,
    #[serde(default)]
    pub worlds: Vec<IrWorldDecl>,
    #[serde(default)]
    pub capability_imports: Vec<IrCapabilityImport>,
    #[serde(default)]
    pub effect_rows: Vec<IrEffectRow>,
    #[serde(default)]
    pub invocation_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervision: Option<IrSupervision>,
    #[serde(default)]
    pub compensation: Vec<IrCompensationHint>,
    #[serde(default)]
    pub channel_surface_hints: Vec<IrChannelHint>,
    #[serde(default)]
    pub authority_checks: Vec<IrAuthorityCheck>,
    pub node_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_node: Option<String>,
    pub compiled_at_ms: i64,
}

/// Declared contract interface (inputs/outputs/tools).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrInterfaceDecl {
    pub name: String,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
}

/// World import/export placeholder (typed worlds land as CCL grows).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrWorldDecl {
    pub name: String,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub exports: Vec<String>,
}

/// Capability requested by the contract (not a grant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrCapabilityImport {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub attenuations: Vec<String>,
}

/// Parameterized effect row — each mutating row must enter ActionBinding/PATE.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IrEffectRow {
    pub node_id: String,
    pub kind: String,
    pub mutates: bool,
    pub requires_admission: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_verb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrSupervision {
    pub initial_state: String,
    #[serde(default)]
    pub terminal_states: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrCompensationHint {
    pub node_id: String,
    pub hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrChannelHint {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrAuthorityCheck {
    pub kind: String,
    pub subject: String,
}

impl ConnectorIrV1 {
    /// Recompute `ir_cid` from a body that excludes the cid field itself.
    pub fn seal(mut self) -> Self {
        self.schema = CONNECTOR_IR_V1_SCHEMA.into();
        let body = serde_json::json!({
            "schema": self.schema,
            "solution_contract_cid": self.solution_contract_cid,
            "name": self.name,
            "version": self.version,
            "domain": self.domain,
            "interfaces": self.interfaces,
            "worlds": self.worlds,
            "capability_imports": self.capability_imports,
            "effect_rows": self.effect_rows,
            "invocation_modes": self.invocation_modes,
            "supervision": self.supervision,
            "compensation": self.compensation,
            "channel_surface_hints": self.channel_surface_hints,
            "authority_checks": self.authority_checks,
            "node_count": self.node_count,
            "entry_node": self.entry_node,
            // Exclude compiled_at_ms for digest stability across timestamps.
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        self.ir_cid = format!("cir1-sha256-{}", digest_hex(&bytes));
        self
    }

    /// True when any effect row requires admission (mutating world effects).
    pub fn requires_admission(&self) -> bool {
        self.effect_rows.iter().any(|r| r.requires_admission)
    }

    /// Effect rows that mutate world state.
    pub fn mutating_effects(&self) -> impl Iterator<Item = &IrEffectRow> {
        self.effect_rows.iter().filter(|r| r.mutates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_is_stable_for_same_body() {
        let mk = || {
            ConnectorIrV1 {
                schema: CONNECTOR_IR_V1_SCHEMA.into(),
                ir_cid: String::new(),
                solution_contract_cid: Some("cls1-sha256-abc".into()),
                name: "demo".into(),
                version: "1.0.0".into(),
                domain: None,
                interfaces: vec![],
                worlds: vec![],
                capability_imports: vec![],
                effect_rows: vec![IrEffectRow {
                    node_id: "n1".into(),
                    kind: "tool_call".into(),
                    mutates: true,
                    requires_admission: true,
                    target: Some("lookup".into()),
                    semantic_verb: Some("invoke".into()),
                    channel_hint: Some("native".into()),
                }],
                invocation_modes: vec!["call".into()],
                supervision: None,
                compensation: vec![],
                channel_surface_hints: vec![],
                authority_checks: vec![],
                node_count: 1,
                entry_node: Some("n1".into()),
                compiled_at_ms: 1,
            }
            .seal()
        };
        let a = mk();
        let b = mk();
        assert_eq!(a.ir_cid, b.ir_cid);
        assert!(a.ir_cid.starts_with("cir1-sha256-"));
        assert!(a.requires_admission());
    }
}
