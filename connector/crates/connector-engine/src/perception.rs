//! Perception Engine — unified observation and context retrieval.
//!
//! Wraps: Memory + Grounding + Claims + Judgment + Trace
//!
//! Every observation is CID-backed. Every perception is scored.
//!
//! ## Two core operations:
//! - `observe()` — take raw input, write to kernel, extract claims, ground, judge
//! - `perceive()` — retrieve relevant context for current situation

use vac_core::kernel::MemoryKernel;
use vac_core::types::*;
use crate::memory::{MemoryCoordinator, PacketSummary};
use crate::grounding::GroundingTable;
use crate::claims::{Claim, ClaimVerifier, ClaimSet};
use crate::judgment::{JudgmentEngine, JudgmentResult, JudgmentConfig};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Observation — result of observing raw input
// ═══════════════════════════════════════════════════════════════

/// Result of observing raw input through the perception engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// CID of the stored memory packet
    pub cid: String,
    /// Extracted entities from the content
    pub entities: Vec<String>,
    /// Extracted claims (if claim extraction was requested)
    pub claims: Option<ClaimSet>,
    /// Quality score from judgment engine (0-100)
    pub quality_score: u32,
    /// Quality grade (A+, A, B, C, D, F)
    pub quality_grade: String,
    /// Warnings from observation pipeline
    pub warnings: Vec<String>,
    /// Timestamp of observation
    pub timestamp: i64,
}

// ═══════════════════════════════════════════════════════════════
// PerceivedContext — result of perceiving current situation
// ═══════════════════════════════════════════════════════════════

/// Perceived context for the current situation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerceivedContext {
    /// Relevant memory packets found
    pub memories: Vec<PacketSummary>,
    /// Total memories found before limit
    pub total_found: usize,
    /// Judgment of current kernel state
    pub judgment: JudgmentResult,
    /// Active session (if any)
    pub active_session: Option<String>,
    /// Namespace being perceived
    pub namespace: String,
}

// ═══════════════════════════════════════════════════════════════
// ObservationConfig — controls observation behavior
// ═══════════════════════════════════════════════════════════════

/// Configuration for observation behavior.
#[derive(Debug, Clone)]
pub struct ObservationConfig {
    /// Whether to extract and verify claims
    pub extract_claims: bool,
    /// Packet type for the observation
    pub packet_type: PacketType,
    /// Maximum entities to extract (simple word-based)
    pub max_entities: usize,
    /// Judgment profile to use
    pub judgment_profile: JudgmentConfig,
}

impl Default for ObservationConfig {
    fn default() -> Self {
        Self {
            extract_claims: false,
            packet_type: PacketType::Input,
            max_entities: 20,
            judgment_profile: JudgmentConfig::default(),
        }
    }
}

impl ObservationConfig {
    pub fn with_claims(mut self) -> Self { self.extract_claims = true; self }
    pub fn with_packet_type(mut self, pt: PacketType) -> Self { self.packet_type = pt; self }
    pub fn with_medical_profile(mut self) -> Self {
        self.judgment_profile = JudgmentConfig::medical();
        self.extract_claims = true;
        self
    }
    pub fn with_financial_profile(mut self) -> Self {
        self.judgment_profile = JudgmentConfig::financial();
        self.extract_claims = true;
        self
    }
}

// ═══════════════════════════════════════════════════════════════
// PerceptionEngine
// ═══════════════════════════════════════════════════════════════

/// Unified perception engine — observe and perceive through kernel memory.
pub struct PerceptionEngine;

impl PerceptionEngine {
    /// Observe raw input: write to kernel, extract entities, optionally verify claims.
    ///
    /// Pipeline:
    /// 1. Extract entities from content (simple keyword extraction)
    /// 2. Write to kernel memory (CID-backed)
    /// 3. If claims provided, verify against source text
    /// 4. Score observation quality via Judgment Engine
    /// 5. Return Observation with CID, entities, claims, quality
    pub fn observe(
        kernel: &mut MemoryKernel,
        agent_pid: &str,
        content: &str,
        user: &str,
        pipeline: &str,
        session_id: Option<&str>,
        claims: Option<&[Claim]>,
        grounding: Option<&GroundingTable>,
        config: &ObservationConfig,
    ) -> Result<Observation, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut warnings = Vec::new();

        // 1. Extract entities (simple: split on entity-like patterns)
        let entities = extract_entities(content, config.max_entities);

        // 2. Ground entities if grounding table available
        let mut tags = Vec::new();
        if let Some(table) = grounding {
            for entity in &entities {
                for cat in table.categories() {
                    if let Some(entry) = table.lookup_fuzzy(cat, entity) {
                        tags.push(format!("{}:{}", entry.code, entry.desc));
                    }
                }
            }
        }

        // 3. Write to kernel memory
        let cid = MemoryCoordinator::write(
            kernel, agent_pid, content, user, pipeline,
            config.packet_type.clone(), session_id,
            entities.clone(), tags,
        )?;

        // 4. Verify claims if provided
        let claim_set = if config.extract_claims {
            if let Some(claims_list) = claims {
                let cs = ClaimVerifier::verify(claims_list, content, &cid.to_string());
                if cs.rejected_count() > 0 {
                    warnings.push(format!("{} claims rejected", cs.rejected_count()));
                }
                if cs.needs_review_count() > 0 {
                    warnings.push(format!("{} claims need review", cs.needs_review_count()));
                }
                Some(cs)
            } else {
                None
            }
        } else {
            None
        };

        // 5. Score quality via Judgment Engine
        let judgment = JudgmentEngine::judge(kernel, claim_set.as_ref(), &config.judgment_profile);
        if !judgment.warnings.is_empty() {
            warnings.extend(judgment.warnings.clone());
        }

        Ok(Observation {
            cid: cid.to_string(),
            entities,
            claims: claim_set,
            quality_score: judgment.score,
            quality_grade: judgment.grade,
            warnings,
            timestamp: now,
        })
    }

    /// Perceive current situation: retrieve relevant context from kernel memory.
    ///
    /// Pipeline:
    /// 1. Search namespace for recent packets
    /// 2. Optionally search session for conversation context
    /// 3. Score current kernel state via Judgment Engine
    /// 4. Return PerceivedContext with memories and quality assessment
    pub fn perceive(
        kernel: &MemoryKernel,
        namespace: &str,
        session_id: Option<&str>,
        limit: usize,
        config: &JudgmentConfig,
    ) -> PerceivedContext {
        // 1. Search namespace
        let mut memories = MemoryCoordinator::search_namespace(kernel, namespace, limit);
        let total_found = memories.len();

        // 2. If session provided, also search session and merge
        if let Some(sid) = session_id {
            let session_memories = MemoryCoordinator::search_session(kernel, sid, limit);
            for sm in session_memories {
                if !memories.iter().any(|m| m.cid == sm.cid) {
                    memories.push(sm);
                }
            }
        }

        // 3. Sort by timestamp descending (most recent first)
        memories.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        if memories.len() > limit {
            memories.truncate(limit);
        }

        // 4. Judge current kernel state
        let judgment = JudgmentEngine::judge(kernel, None, config);

        PerceivedContext {
            memories,
            total_found,
            judgment,
            active_session: session_id.map(|s| s.to_string()),
            namespace: namespace.to_string(),
        }
    }

    /// Quick observe — minimal config, just write and score.
    pub fn quick_observe(
        kernel: &mut MemoryKernel,
        agent_pid: &str,
        content: &str,
        user: &str,
        pipeline: &str,
    ) -> Result<Observation, String> {
        Self::observe(kernel, agent_pid, content, user, pipeline, None, None, None, &ObservationConfig::default())
    }
}

// ═══════════════════════════════════════════════════════════════
// Entity extraction (simple keyword-based)
// ═══════════════════════════════════════════════════════════════

/// Extract entity-like tokens from text.
/// Simple heuristic: words with colons (entity:id), capitalized multi-word phrases,
/// and medical/technical terms.
fn extract_entities(text: &str, max: usize) -> Vec<String> {
    let mut entities = Vec::new();

    // 1. Explicit entity references (entity:id format)
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != ':' && c != '_');
        if clean.contains(':') && clean.len() > 3 {
            if !entities.contains(&clean.to_string()) {
                entities.push(clean.to_string());
            }
        }
    }

    // 2. Capitalized phrases (likely proper nouns / medical terms)
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut i = 0;
    while i < words.len() && entities.len() < max {
        let w = words[i].trim_matches(|c: char| !c.is_alphanumeric());
        if !w.is_empty() && w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) && w.len() > 2 {
            // Check for multi-word capitalized phrase
            let mut phrase = vec![w.to_string()];
            let mut j = i + 1;
            while j < words.len() {
                let nw = words[j].trim_matches(|c: char| !c.is_alphanumeric());
                if !nw.is_empty() && nw.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                    phrase.push(nw.to_string());
                    j += 1;
                } else {
                    break;
                }
            }
            let entity = phrase.join(" ");
            if entity.len() > 2 && !entities.contains(&entity) {
                // Skip common English words
                let lower = entity.to_lowercase();
                if !["the", "and", "for", "with", "from", "this", "that", "has", "was", "are"]
                    .contains(&lower.as_str())
                {
                    entities.push(entity);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }

    entities.truncate(max);
    entities
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{SyscallRequest, SyscallPayload, SyscallValue};
    use crate::claims::{Evidence, SupportLevel};

    fn setup() -> (MemoryKernel, String) {
        let mut k = MemoryKernel::new();
        let r = k.dispatch(SyscallRequest {
            agent_pid: "system".into(), operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "bot".into(), namespace: "ns:bot".into(),
                role: Some("writer".into()), model: None, framework: None,
            }, reason: None, vakya_id: None,
        });
        let pid = match r.value { SyscallValue::AgentPid(p) => p, _ => panic!() };
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(), operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty, reason: None, vakya_id: None,
        });
        (k, pid)
    }

    #[test]
    fn test_quick_observe() {
        let (mut k, pid) = setup();
        let obs = PerceptionEngine::quick_observe(&mut k, &pid, "patient has chest pain", "user:doc", "pipe:er").unwrap();
        assert!(!obs.cid.is_empty());
        assert!(obs.quality_score > 0);
        assert!(!obs.quality_grade.is_empty());
    }

    #[test]
    fn test_observe_with_entities() {
        let (mut k, pid) = setup();
        let obs = PerceptionEngine::observe(
            &mut k, &pid, "patient:001 has condition:diabetes and symptom:chest_pain",
            "user:doc", "pipe:er", None, None, None, &ObservationConfig::default(),
        ).unwrap();
        assert!(obs.entities.contains(&"patient:001".to_string()));
        assert!(obs.entities.contains(&"condition:diabetes".to_string()));
    }

    #[test]
    fn test_observe_with_claims() {
        let (mut k, pid) = setup();
        let claims = vec![
            Claim {
                item: "chest pain".into(), category: "symptoms".into(),
                evidence: Evidence {
                    source_cid: "cid:test".into(), field_path: None,
                    quote: "chest pain".into(), support: SupportLevel::Explicit,
                }, code: Some("R07.9".into()), code_desc: Some("Chest pain".into()),
            },
        ];
        let config = ObservationConfig::default().with_claims();
        let obs = PerceptionEngine::observe(
            &mut k, &pid, "patient presents with chest pain",
            "user:doc", "pipe:er", None, Some(&claims), None, &config,
        ).unwrap();
        assert!(obs.claims.is_some());
        let cs = obs.claims.unwrap();
        assert_eq!(cs.confirmed_count(), 1);
    }

    #[test]
    fn test_observe_with_grounding() {
        let (mut k, pid) = setup();
        let json = r#"{"conditions": {"diabetes": {"code": "E11.9", "desc": "Type 2 DM"}}}"#;
        let table = GroundingTable::from_json(json).unwrap();
        let obs = PerceptionEngine::observe(
            &mut k, &pid, "patient has diabetes",
            "user:doc", "pipe:er", None, None, Some(&table), &ObservationConfig::default(),
        ).unwrap();
        assert!(!obs.cid.is_empty());
    }

    #[test]
    fn test_perceive_namespace() {
        let (mut k, pid) = setup();
        // Write some data
        for i in 0..3 {
            PerceptionEngine::quick_observe(&mut k, &pid, &format!("observation {}", i), "user:doc", "pipe:er").unwrap();
        }
        let ctx = PerceptionEngine::perceive(&k, "ns:bot", None, 10, &JudgmentConfig::default());
        assert_eq!(ctx.memories.len(), 3);
        assert_eq!(ctx.namespace, "ns:bot");
        assert!(ctx.judgment.score > 0);
    }

    #[test]
    fn test_perceive_with_session() {
        let (mut k, pid) = setup();
        let sid = MemoryCoordinator::create_session(&mut k, &pid, Some("test")).unwrap();
        let config = ObservationConfig::default();
        PerceptionEngine::observe(
            &mut k, &pid, "session observation",
            "user:doc", "pipe:er", Some(&sid), None, None, &config,
        ).unwrap();
        let ctx = PerceptionEngine::perceive(&k, "ns:bot", Some(&sid), 10, &JudgmentConfig::default());
        assert!(ctx.memories.len() >= 1);
        assert_eq!(ctx.active_session, Some(sid));
    }

    #[test]
    fn test_extract_entities() {
        let entities = extract_entities("patient:001 has condition:diabetes", 10);
        assert!(entities.contains(&"patient:001".to_string()));
        assert!(entities.contains(&"condition:diabetes".to_string()));
    }

    #[test]
    fn test_medical_profile() {
        let (mut k, pid) = setup();
        let config = ObservationConfig::default().with_medical_profile();
        assert!(config.extract_claims);
        let obs = PerceptionEngine::observe(
            &mut k, &pid, "patient has STEMI",
            "user:doc", "pipe:er", None, None, None, &config,
        ).unwrap();
        assert!(obs.quality_score > 0);
    }
}
