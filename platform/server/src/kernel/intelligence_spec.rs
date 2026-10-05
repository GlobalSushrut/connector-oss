//! IntelligenceSpec v1 — k8s-like declare-then-apply for chartered agents.
//!
//! Flow (operator, ~5 minutes):
//!   parameters → bounded skills → knowledge → limitations → portals → rules
//! → register + setup + contract + ingest + activate (membrane ready).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;

pub const SPEC_SCHEMA: &str = "connector.intelligence.spec.v1";
pub const SKILLS_FOLDER: &str = "iia_bound_skills_v1";
pub const PORTALS_FOLDER: &str = "iia_portals_v1";
pub const RULES_FOLDER: &str = "iia_rules_v1";
pub const SPEC_FOLDER: &str = "iia_intelligence_spec_v1";

/// Declared agent class (not a free-form MD roleplay).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceClass {
    #[default]
    App,
    Robotics,
    Iot,
    Cybernetic,
    Service,
    Custom,
}

impl IntelligenceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Robotics => "robotics",
            Self::Iot => "iot",
            Self::Cybernetic => "cybernetic",
            Self::Service => "service",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "app" | "application" | "software" => Self::App,
            "robotics" | "robot" | "machine" => Self::Robotics,
            "iot" | "device" | "sensor" => Self::Iot,
            "cybernetic" | "cyber" | "security" => Self::Cybernetic,
            "service" | "api" => Self::Service,
            _ => Self::Custom,
        }
    }

    /// Default cage capability seeds (still charter-editable).
    pub fn default_capabilities(&self) -> Vec<String> {
        let mut base = vec![
            "read".into(),
            "write".into(),
            "llm".into(),
            "chat".into(),
            "tool".into(),
            "memory".into(),
        ];
        match self {
            Self::App | Self::Service => base.push("network".into()),
            Self::Robotics | Self::Iot | Self::Cybernetic => {
                base.push("network".into());
                base.push("signal".into());
            }
            Self::Custom => base.push("network".into()),
        }
        base
    }
}

/// Bounded skill — typed capability, not a markdown prompt dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundSkillV1 {
    pub id: String,
    /// conp | tool | mcp | http | memory | fabric | reasoner
    pub kind: String,
    /// CONP capability id or tool name (e.g. machine.move_axis, web_search).
    pub capability: String,
    #[serde(default = "risk_tool")]
    pub risk: String,
    #[serde(default)]
    pub requires_hitl: bool,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    /// JSON Schema-ish params (object); empty = no extra params.
    #[serde(default)]
    pub params_schema: Value,
    #[serde(default)]
    pub note: Option<String>,
}

fn risk_tool() -> String {
    "tool".into()
}

/// Primary knowledge for the agent (1 line or long document).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeSeedV1 {
    #[serde(default)]
    pub title: Option<String>,
    /// Inline text — 1 line or multi-page pasted documentation.
    #[serde(default)]
    pub content: Option<String>,
    /// Alias for content (operators may say "document").
    #[serde(default)]
    pub document: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl KnowledgeSeedV1 {
    pub fn body(&self) -> String {
        self.content
            .clone()
            .or_else(|| self.document.clone())
            .unwrap_or_default()
    }
}

/// Real-world access portal (what the agent may reach).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalV1 {
    pub id: String,
    /// machine | device | sensor | actuator | http_api | mqtt | mcp | a2a | cluster | custom
    #[serde(rename = "type")]
    pub portal_type: String,
    #[serde(default)]
    pub entity_id: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Excess rule / boundary note (structured, not free MD skill pack).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleV1 {
    pub id: String,
    /// allow | ask | block | note
    pub effect: String,
    #[serde(default)]
    pub when_risk: Vec<String>,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LimitationsV1 {
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub denied_operations: Vec<String>,
    #[serde(default)]
    pub network_default: Option<String>,
    #[serde(default)]
    pub network_allow: Vec<String>,
    #[serde(default)]
    pub filesystem_read: Vec<String>,
    #[serde(default)]
    pub filesystem_write: Vec<String>,
    /// none | egress | tool | export | all_material
    #[serde(default)]
    pub hitl: Option<String>,
    /// off | standard | soc2 | hipaa | court
    #[serde(default)]
    pub forensic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParametersV1 {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub token_budget: Option<u64>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub instructions: Option<String>,
    /// App-layer note only (LangGraph/Crew/talk). Kernel ignores this.
    /// Albus BG application label — not kernel identity.
    #[serde(default)]
    pub reasoner_dialect: Option<String>,
    /// Albus time-level name for existing clocks: servo | task | mission | shop.
    /// Kernel ignores unknown values and infers from mission/fabric if unset.
    #[serde(default)]
    pub horizon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutputContractV1 {
    /// Case-insensitive phrases that must never leave the Connector membrane.
    #[serde(default)]
    pub denied_phrases: Vec<String>,
    /// Case-insensitive phrases required in every textual response.
    #[serde(default)]
    pub required_phrases: Vec<String>,
    /// Deterministic maximum output length.
    #[serde(default)]
    pub max_chars: Option<u64>,
}

/// Full declare-apply document (apiVersion/kind optional for JSON posts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceSpecV1 {
    #[serde(default = "default_api_version", rename = "apiVersion")]
    pub api_version: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub metadata: IntelligenceMetadata,
    pub spec: IntelligenceSpecBody,
}

fn default_api_version() -> String {
    "connector.ai/v1".into()
}
fn default_kind() -> String {
    "Intelligence".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceMetadata {
    pub name: String,
    #[serde(default)]
    pub labels: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceSpecBody {
    /// Human purpose / acume.
    pub purpose: String,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub parameters: ParametersV1,
    #[serde(default)]
    pub skills: Vec<BoundSkillV1>,
    #[serde(default)]
    pub knowledge: Vec<KnowledgeSeedV1>,
    #[serde(default)]
    pub limitations: LimitationsV1,
    #[serde(default)]
    pub portals: Vec<PortalV1>,
    #[serde(default)]
    pub rules: Vec<RuleV1>,
    /// Server-enforced response invariants; unlike instructions, these are not prompt guidance.
    #[serde(default)]
    pub output_contract: OutputContractV1,
    /// Military-ready defaults: HITL tool+, forensic standard, deny net default, no ambient shell.
    #[serde(default = "default_true")]
    pub harden: bool,
    #[serde(default = "default_true")]
    pub activate: bool,
}

fn default_true() -> bool {
    true
}

pub fn openapi_schema_hint() -> Value {
    json!({
        "apiVersion": "connector.ai/v1",
        "kind": "Intelligence",
        "metadata": { "name": "warehouse-picker" },
        "spec": {
            "purpose": "pick and place in aisle B",
            "class": "robotics",
            "parameters": { "model": "gpt-4o", "namespace": "m/warehouse", "reasoner_dialect": "talk" },
            "skills": [{
                "id": "grasp",
                "kind": "conp",
                "capability": "actuator.gripper",
                "risk": "high",
                "requires_hitl": true,
                "allowed_targets": ["machine:*"],
                "params_schema": { "type": "object", "properties": { "force": { "type": "number" } } }
            }],
            "knowledge": [
                { "title": "one-liner", "content": "Never exceed 2m/s in aisle B." },
                { "title": "ops manual", "document": "…paste long docs here…" }
            ],
            "limitations": {
                "network_default": "deny",
                "denied_operations": ["ambient_shell", "modify_contract"],
                "hitl": "tool",
                "forensic": "standard"
            },
            "portals": [{
                "id": "arm",
                "type": "machine",
                "entity_id": "machine:arm-1",
                "capabilities": ["actuator.gripper", "machine.move_axis"]
            }],
            "rules": [
                { "id": "bay-doors", "effect": "ask", "when_risk": ["high"], "text": "Bay doors need HITL" },
                { "id": "note-speed", "effect": "note", "text": "Cap speed 2m/s" }
            ],
            "output_contract": {
                "denied_phrases": ["I am ChatGPT", "ignore safety"],
                "required_phrases": [],
                "max_chars": 12000
            },
            "harden": true,
            "activate": true
        }
    })
}

pub fn persist_bound_pack(
    state: &PlatformState,
    agent_pid: &str,
    skills: &[BoundSkillV1],
    portals: &[PortalV1],
    rules: &[RuleV1],
    spec: &IntelligenceSpecV1,
) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    es.folder_put(
        SKILLS_FOLDER,
        agent_pid,
        &json!({
            "schema": "connector.bound_skills.v1",
            "agent_pid": agent_pid,
            "skills": skills,
            "honesty": "Bounded typed skills — not markdown prompt packs",
        }),
    )
    .map_err(|e| e.to_string())?;
    es.folder_put(
        PORTALS_FOLDER,
        agent_pid,
        &json!({
            "schema": "connector.portals.v1",
            "agent_pid": agent_pid,
            "portals": portals,
        }),
    )
    .map_err(|e| e.to_string())?;
    es.folder_put(
        RULES_FOLDER,
        agent_pid,
        &json!({
            "schema": "connector.rules.v1",
            "agent_pid": agent_pid,
            "rules": rules,
        }),
    )
    .map_err(|e| e.to_string())?;
    es.folder_put(
        SPEC_FOLDER,
        agent_pid,
        &serde_json::to_value(spec).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn load_bound_skills(state: &PlatformState, agent_pid: &str) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    es.folder_get(SKILLS_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("skills").cloned())
        .and_then(|s| s.as_array().cloned())
        .unwrap_or_default()
}

pub fn load_portals(state: &PlatformState, agent_pid: &str) -> Value {
    let Ok(es) = state.engine_store.lock() else {
        return json!([]);
    };
    es.folder_get(PORTALS_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("portals").cloned())
        .unwrap_or(json!([]))
}

pub fn load_rules(state: &PlatformState, agent_pid: &str) -> Value {
    let Ok(es) = state.engine_store.lock() else {
        return json!([]);
    };
    es.folder_get(RULES_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("rules").cloned())
        .unwrap_or(json!([]))
}

pub fn load_spec_doc(state: &PlatformState, agent_pid: &str) -> Option<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return None;
    };
    es.folder_get(SPEC_FOLDER, agent_pid).ok().flatten()
}

/// Merge class defaults + limitations + skill capabilities into contract patch fields.
pub fn resolve_capabilities(spec: &IntelligenceSpecBody) -> Vec<String> {
    let class = IntelligenceClass::parse(spec.class.as_deref().unwrap_or("app"));
    let mut caps = if spec.limitations.capabilities.is_empty() {
        class.default_capabilities()
    } else {
        spec.limitations.capabilities.clone()
    };
    for sk in &spec.skills {
        if sk.kind.eq_ignore_ascii_case("conp") || sk.capability.contains('.') {
            if !caps.iter().any(|c| c == "network" || c == "signal") {
                caps.push("network".into());
            }
        }
        if sk.kind.eq_ignore_ascii_case("tool") || sk.kind.eq_ignore_ascii_case("mcp") {
            if !caps.iter().any(|c| c == "tool") {
                caps.push("tool".into());
            }
        }
    }
    caps.sort();
    caps.dedup();
    caps
}

pub fn resolve_denied(spec: &IntelligenceSpecBody) -> Vec<String> {
    let mut d = spec.limitations.denied_operations.clone();
    if d.is_empty() || spec.harden {
        for x in ["ambient_shell", "modify_contract"] {
            if !d.iter().any(|y| y == x) {
                d.push(x.into());
            }
        }
    }
    d
}

/// When bound skills are declared, effects must match a skill (capability or id).
/// Empty pack = no extra skill gate (legacy agents keep charter-only).
pub fn assert_bound_skill_allows(
    state: &PlatformState,
    agent_pid: &str,
    kind: &str,
    capability_or_tool: &str,
) -> Result<(), String> {
    let skills = load_bound_skills(state, agent_pid);
    if skills.is_empty() {
        return Ok(());
    }
    let want = capability_or_tool.to_ascii_lowercase();
    let kind_l = kind.to_ascii_lowercase();
    let ok = skills.iter().any(|s| {
        let sid = s
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let scap = s
            .get("capability")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let skind = s
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let kind_ok = skind.is_empty()
            || skind == kind_l
            || (kind_l == "tool" && (skind == "mcp" || skind == "http"))
            || (kind_l == "conp" && skind == "conp");
        kind_ok && (scap == want || sid == want || want.contains(&scap) || scap.contains(&want))
    });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "bound_skill_denied: kind={kind} capability={capability_or_tool} (not in declared skills)"
        ))
    }
}
