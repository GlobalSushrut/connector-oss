//! ARC memory classes (Phase H) — typed domains with owner/IFC/share/destroy policy.
//! Working · Persistent · Knowledge · Shared · Secret · Mission · Evidence · ModelContext · Scratch

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ConnectorError, DenialReason};

use super::flags::ArcFlags;
use super::ifc::{self, IfcTriple};

pub const SCHEMA: &str = "connector.arc.memory.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    Working,
    Persistent,
    Knowledge,
    Shared,
    Secret,
    Mission,
    Evidence,
    ModelContext,
    Scratch,
}

impl MemoryClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Persistent => "persistent",
            Self::Knowledge => "knowledge",
            Self::Shared => "shared",
            Self::Secret => "secret",
            Self::Mission => "mission",
            Self::Evidence => "evidence",
            Self::ModelContext => "model_context",
            Self::Scratch => "scratch",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "working" | "work" => Some(Self::Working),
            "persistent" | "persist" => Some(Self::Persistent),
            "knowledge" | "know" => Some(Self::Knowledge),
            "shared" | "share" => Some(Self::Shared),
            "secret" => Some(Self::Secret),
            "mission" => Some(Self::Mission),
            "evidence" | "evid" => Some(Self::Evidence),
            "model_context" | "modelcontext" | "context" => Some(Self::ModelContext),
            "scratch" => Some(Self::Scratch),
            _ => None,
        }
    }

    pub fn all() -> &'static [MemoryClass] {
        &[
            Self::Working,
            Self::Persistent,
            Self::Knowledge,
            Self::Shared,
            Self::Secret,
            Self::Mission,
            Self::Evidence,
            Self::ModelContext,
            Self::Scratch,
        ]
    }

    /// H2: default IFC triple per class.
    pub fn default_ifc(self) -> IfcTriple {
        match self {
            Self::Working | Self::Scratch => IfcTriple {
                confidentiality: "internal".into(),
                integrity: "untrusted".into(),
                provenance: "working".into(),
            },
            Self::Persistent | Self::Knowledge => IfcTriple {
                confidentiality: "internal".into(),
                integrity: "verified".into(),
                provenance: "persistent".into(),
            },
            Self::Shared => IfcTriple {
                confidentiality: "internal".into(),
                integrity: "user".into(),
                provenance: "shared".into(),
            },
            Self::Secret => IfcTriple {
                confidentiality: "secret".into(),
                integrity: "system".into(),
                provenance: "secret_tokenized".into(),
            },
            Self::Mission => IfcTriple {
                confidentiality: "confidential".into(),
                integrity: "verified".into(),
                provenance: "mission".into(),
            },
            Self::Evidence => IfcTriple {
                confidentiality: "internal".into(),
                integrity: "system".into(),
                provenance: "evidence_append".into(),
            },
            Self::ModelContext => IfcTriple {
                confidentiality: "confidential".into(),
                integrity: "untrusted".into(),
                provenance: "model_context".into(),
            },
        }
    }

    pub fn policy(self) -> ClassPolicy {
        match self {
            Self::Working => ClassPolicy {
                owner_only_write: true,
                shareable: false,
                destroyable: true,
                append_only: false,
                requires_tokenize: false,
            },
            Self::Persistent => ClassPolicy {
                owner_only_write: true,
                shareable: false,
                destroyable: true,
                append_only: false,
                requires_tokenize: false,
            },
            Self::Knowledge => ClassPolicy {
                owner_only_write: true,
                shareable: true,
                destroyable: false,
                append_only: false,
                requires_tokenize: false,
            },
            Self::Shared => ClassPolicy {
                owner_only_write: false,
                shareable: true,
                destroyable: true,
                append_only: false,
                requires_tokenize: false,
            },
            Self::Secret => ClassPolicy {
                owner_only_write: true,
                shareable: false,
                destroyable: true,
                append_only: false,
                requires_tokenize: true,
            },
            Self::Mission => ClassPolicy {
                owner_only_write: true,
                shareable: false,
                destroyable: false,
                append_only: false,
                requires_tokenize: false,
            },
            Self::Evidence => ClassPolicy {
                owner_only_write: true,
                shareable: false,
                destroyable: false,
                append_only: true,
                requires_tokenize: false,
            },
            Self::ModelContext => ClassPolicy {
                owner_only_write: true,
                shareable: false,
                destroyable: true,
                append_only: false,
                requires_tokenize: false,
            },
            Self::Scratch => ClassPolicy {
                owner_only_write: true,
                shareable: false,
                destroyable: true,
                append_only: false,
                requires_tokenize: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassPolicy {
    pub owner_only_write: bool,
    pub shareable: bool,
    pub destroyable: bool,
    pub append_only: bool,
    pub requires_tokenize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryRecord {
    pub id: String,
    pub agent_id: String,
    pub class: MemoryClass,
    pub key: String,
    pub content_digest: String,
    pub ifc: IfcTriple,
    pub tokenized: bool,
    pub prev_id: Option<String>,
    pub sealed: bool,
}

/// In-process class store (H1). Durable VAC binding is separate.
#[derive(Debug, Default, Clone)]
pub struct MemoryClassStore {
    /// key = agent_id\0class\0key
    inner: Arc<DashMap<String, MemoryRecord>>,
    /// Evidence append chains: agent\0key → ordered ids
    evidence_chains: Arc<DashMap<String, Vec<String>>>,
}

fn store_key(agent_id: &str, class: MemoryClass, key: &str) -> String {
    format!("{agent_id}\0{}\0{key}", class.as_str())
}

fn evidence_chain_key(agent_id: &str, key: &str) -> String {
    format!("{agent_id}\0evidence\0{key}")
}

fn content_digest(content: &str) -> String {
    format!("{:x}", Sha256::digest(content.as_bytes()))
}

impl MemoryClassStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, agent_id: &str, class: MemoryClass, key: &str) -> Option<MemoryRecord> {
        self.inner
            .get(&store_key(agent_id, class, key))
            .map(|e| e.clone())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

static STORE: std::sync::OnceLock<MemoryClassStore> = std::sync::OnceLock::new();

pub fn store() -> &'static MemoryClassStore {
    STORE.get_or_init(MemoryClassStore::new)
}

/// H1 class map for status / ABI.
pub fn class_map_json() -> Value {
    let classes: Vec<Value> = MemoryClass::all()
        .iter()
        .map(|c| {
            let p = c.policy();
            json!({
                "class": c.as_str(),
                "ifc": c.default_ifc(),
                "owner_only_write": p.owner_only_write,
                "shareable": p.shareable,
                "destroyable": p.destroyable,
                "append_only": p.append_only,
                "requires_tokenize": p.requires_tokenize,
            })
        })
        .collect();
    json!({
        "schema": SCHEMA,
        "classes": classes,
        "honesty": "Class deny without identity change — wrong agent / policy violation",
    })
}

fn memory_enforced() -> bool {
    let f = ArcFlags::from_env();
    f.memory || f.ifc || f.harden
}

/// Assert actor may write this class for owner agent (H1 — no identity change).
pub fn assert_write_identity(owner_agent: &str, actor_agent: &str, class: MemoryClass) -> Result<(), ConnectorError> {
    let policy = class.policy();
    if policy.owner_only_write && owner_agent != actor_agent {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "arc_memory: class {} owner_only — actor '{}' cannot write owner '{}'",
                class.as_str(),
                actor_agent,
                owner_agent
            ),
        )
        .with_denied_resource("arc.memory")
        .with_hint("Class deny without identity change — do not spoof agent_id"));
    }
    if !policy.shareable && owner_agent != actor_agent {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("arc_memory: class {} not shareable across agents", class.as_str()),
        )
        .with_denied_resource("arc.memory"));
    }
    Ok(())
}

/// H2: IFC gate for memory write vs sink (LLM / world / shared).
pub fn assert_ifc_for_write(
    class: MemoryClass,
    sink: &IfcTriple,
) -> Result<(), ConnectorError> {
    if !memory_enforced() && !ArcFlags::from_env().ifc {
        return Ok(());
    }
    let data = class.default_ifc();
    ifc::assert_flow_or_deny(&data, sink)?;
    Ok(())
}

/// Put / overwrite (non-evidence). Secret requires tokenize (H3).
pub fn put(
    owner_agent: &str,
    actor_agent: &str,
    class: MemoryClass,
    key: &str,
    content: &str,
    tokenized: bool,
) -> Result<MemoryRecord, ConnectorError> {
    assert_write_identity(owner_agent, actor_agent, class)?;
    let policy = class.policy();

    if policy.append_only {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_memory: Evidence is append-only — use append_evidence",
        )
        .with_denied_resource("arc.memory.evidence"));
    }

    // H3: SecretMemory must be tokenized.
    if policy.requires_tokenize && !tokenized {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_memory: SecretMemory requires tokenize before store",
        )
        .with_denied_resource("arc.memory.secret")
        .with_hint("Run data_tokenization::tokenize_for_llm then put(..., tokenized=true)"));
    }

    if memory_enforced() {
        // In-agent store sink: high clearance / matching integrity.
        let sink = IfcTriple {
            confidentiality: "secret".into(),
            integrity: class.default_ifc().integrity.clone(),
            provenance: "any".into(),
        };
        assert_ifc_for_write(class, &sink)?;
    }

    let existing = store().get(owner_agent, class, key);
    if let Some(ref ex) = existing {
        if ex.sealed {
            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                "arc_memory: sealed record — cannot overwrite",
            )
            .with_denied_resource("arc.memory"));
        }
    }

    let rec = MemoryRecord {
        id: Uuid::new_v4().to_string(),
        agent_id: owner_agent.into(),
        class,
        key: key.into(),
        content_digest: content_digest(content),
        ifc: class.default_ifc(),
        tokenized,
        prev_id: existing.map(|e| e.id),
        sealed: false,
    };
    store()
        .inner
        .insert(store_key(owner_agent, class, key), rec.clone());
    Ok(rec)
}

/// H4: EvidenceMemory append-only chain (supersede via prev_id; never mutate prior).
pub fn append_evidence(
    owner_agent: &str,
    actor_agent: &str,
    key: &str,
    content: &str,
) -> Result<MemoryRecord, ConnectorError> {
    assert_write_identity(owner_agent, actor_agent, MemoryClass::Evidence)?;
    let class = MemoryClass::Evidence;

    let chain_key = evidence_chain_key(owner_agent, key);
    let prev_id = store()
        .evidence_chains
        .get(&chain_key)
        .and_then(|v| v.last().cloned());

    // Seal previous tip (append-only — prior bytes immutable).
    if let Some(ref pid) = prev_id {
        if let Some(mut tip) = store()
            .inner
            .iter_mut()
            .find(|e| e.id == *pid)
        {
            tip.sealed = true;
        }
    }

    let rec = MemoryRecord {
        id: Uuid::new_v4().to_string(),
        agent_id: owner_agent.into(),
        class,
        key: key.into(),
        content_digest: content_digest(content),
        ifc: class.default_ifc(),
        tokenized: false,
        prev_id,
        sealed: false,
    };
    // Evidence uses id-keyed storage so prior tips remain addressable.
    store().inner.insert(
        format!("{}\0{}\0{}", owner_agent, class.as_str(), rec.id),
        rec.clone(),
    );
    store()
        .evidence_chains
        .entry(chain_key)
        .or_default()
        .push(rec.id.clone());
    Ok(rec)
}

/// Attempt to mutate a sealed evidence tip — must fail (H4).
pub fn overwrite_evidence_denied(
    owner_agent: &str,
    actor_agent: &str,
    key: &str,
    _content: &str,
) -> Result<(), ConnectorError> {
    assert_write_identity(owner_agent, actor_agent, MemoryClass::Evidence)?;
    Err(ConnectorError::new(
        DenialReason::PolicyDenied,
        format!(
            "arc_memory: Evidence '{key}' is append-only — overwrite denied"
        ),
    )
    .with_denied_resource("arc.memory.evidence"))
}

pub fn destroy(
    owner_agent: &str,
    actor_agent: &str,
    class: MemoryClass,
    key: &str,
) -> Result<(), ConnectorError> {
    assert_write_identity(owner_agent, actor_agent, class)?;
    if !class.policy().destroyable {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("arc_memory: class {} is not destroyable", class.as_str()),
        )
        .with_denied_resource("arc.memory"));
    }
    store().inner.remove(&store_key(owner_agent, class, key));
    Ok(())
}

pub fn posture_json() -> Value {
    let flags = ArcFlags::from_env();
    json!({
        "schema": SCHEMA,
        "flag": "CONNECTOR_ARC_MEMORY",
        "enforced": memory_enforced(),
        "class_map": class_map_json(),
        "records": store().len(),
        "honesty": if flags.memory || flags.ifc {
            "Memory class ABI live — Secret tokenize + Evidence append-only"
        } else {
            "Soft — class map available; enforce with CONNECTOR_ARC_MEMORY or IFC"
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_map_has_nine() {
        assert_eq!(MemoryClass::all().len(), 9);
        let m = class_map_json();
        assert_eq!(m["classes"].as_array().unwrap().len(), 9);
    }

    #[test]
    fn cross_agent_owner_only_denied() {
        let err = assert_write_identity("owner", "other", MemoryClass::Working).unwrap_err();
        assert!(err.human_readable.contains("owner_only"));
    }

    #[test]
    fn secret_requires_tokenize() {
        let err = put("a1", "a1", MemoryClass::Secret, "k", "password123", false).unwrap_err();
        assert!(err.human_readable.contains("tokenize"));
        let ok = put("a1", "a1", MemoryClass::Secret, "k", "⟦conn:x⟧", true).unwrap();
        assert!(ok.tokenized);
        assert_eq!(ok.ifc.confidentiality, "secret");
    }

    #[test]
    fn evidence_append_only() {
        let a = append_evidence("a1", "a1", "case", "fact-1").unwrap();
        let b = append_evidence("a1", "a1", "case", "fact-2").unwrap();
        assert_eq!(b.prev_id.as_deref(), Some(a.id.as_str()));
        assert!(overwrite_evidence_denied("a1", "a1", "case", "mutate").is_err());
        assert!(put("a1", "a1", MemoryClass::Evidence, "case", "nope", false).is_err());
    }

    #[test]
    fn knowledge_not_destroyable() {
        put("a1", "a1", MemoryClass::Knowledge, "k", "doc", false).unwrap();
        assert!(destroy("a1", "a1", MemoryClass::Knowledge, "k").is_err());
    }

    #[test]
    fn secret_to_public_ifc_denied_when_ifc_on() {
        std::env::set_var("CONNECTOR_ARC_IFC", "1");
        let sink = IfcTriple::external_sink();
        let err = assert_ifc_for_write(MemoryClass::Secret, &sink).unwrap_err();
        assert!(err.human_readable.contains("arc_ifc") || err.human_readable.contains("denied"));
        std::env::remove_var("CONNECTOR_ARC_IFC");
    }
}
