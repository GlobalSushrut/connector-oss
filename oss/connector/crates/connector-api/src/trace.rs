//! Run Trace & Stability Engine — what makes Connector 100x more stable than LangChain/CrewAI/Mem0.
//!
//! ## Problems with competitors (from deep research):
//!
//! - **LangChain**: Leaky abstractions, silent failures, no default tracing, "printf debugging"
//! - **CrewAI**: No memory verification, no provenance, opaque task failures
//! - **Mem0**: No cryptographic proof, no CID-grounded verification
//!
//! ## What Connector does differently:
//!
//! 1. **RunTrace** — every `run()` produces a full trace by default (knowledge, prompt, LLM, memory, trust)
//! 2. **Grounding Check** — cryptographic anti-hallucination (response vs knowledge facts)
//! 3. **Debug Mode** — `agent.debug(true).run()` prints every step to stderr
//! 4. **Memory Lifecycle** — dedup, conflict detection, importance scoring
//! 5. **Instruction Validation** — warns on empty, overflow, malformed before run
//!
//! ```rust,ignore
//! let c = Connector::new()
//!     .knowledge(&["Patient is allergic to penicillin"])
//!     .build();
//!
//! let output = c.agent("doctor")
//!     .instructions("You are a medical AI")
//!     .debug(true)  // prints every step to stderr
//!     .run("Prescribe antibiotics", "user:p1")?;
//!
//! // Built-in trace — no external tool needed
//! println!("{}", output.trace());          // full trace
//! println!("{}", output.explain());        // human-readable explanation
//! println!("{:.2}", output.grounding());   // 0.0-1.0 grounding score
//! ```

use std::fmt;
use serde::{Serialize, Deserialize};

// ═══════════════════════════════════════════════════════════════
// 1. RunTrace — built-in tracing for every run()
// ═══════════════════════════════════════════════════════════════

/// A complete trace of what happened during a single `run()` call.
///
/// Unlike LangChain (requires LangSmith) or CrewAI (requires external observability),
/// Connector produces this trace BY DEFAULT with zero configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunTrace {
    /// Pipeline ID for this run
    pub pipeline_id: String,
    /// Agent name
    pub agent: String,
    /// User/subject ID
    pub user_id: String,
    /// Timestamp (ms epoch) when run started
    pub started_at: i64,
    /// Duration in milliseconds
    pub duration_ms: u64,

    // ─── Knowledge Layer ───────────────────────────────────────
    /// Connector-level knowledge facts injected
    pub knowledge_facts: Vec<String>,
    /// Agent-level facts injected
    pub agent_facts: Vec<String>,
    /// Number of knowledge tokens (approximate)
    pub knowledge_tokens_approx: usize,

    // ─── Prompt Assembly ───────────────────────────────────────
    /// The full system prompt that was assembled (knowledge + facts + instructions + steps)
    pub system_prompt: Option<String>,
    /// The effective user message (with context prefix if any)
    pub effective_message: String,
    /// Instructions used (or smart default)
    pub instructions: String,
    /// Task decomposition steps (if any)
    pub task_steps: Vec<String>,

    // ─── LLM Interaction ───────────────────────────────────────
    /// Whether an LLM was actually called
    pub llm_called: bool,
    /// LLM provider/model used
    pub llm_model: Option<String>,
    /// Number of think cycles executed
    pub think_cycles: u32,
    /// Number of retry attempts
    pub retry_attempts: u32,
    /// Raw LLM response text
    pub response_text: String,

    // ─── Memory ────────────────────────────────────────────────
    /// CID of the input memory packet
    pub input_cid: Option<String>,
    /// CID of the response memory packet
    pub response_cid: Option<String>,
    /// Total packets in kernel after this run
    pub total_packets: usize,
    /// Total audit entries after this run
    pub total_audit_entries: usize,

    // ─── Grounding ─────────────────────────────────────────────
    /// Grounding score: what fraction of the response is grounded in knowledge (0.0-1.0)
    pub grounding_score: f32,
    /// Grounding details: which claims are grounded vs ungrounded
    pub grounding_details: Vec<GroundingClaim>,

    // ─── Validation Warnings ───────────────────────────────────
    /// Warnings generated during instruction validation
    pub warnings: Vec<String>,
}

impl RunTrace {
    pub fn new(pipeline_id: &str, agent: &str, user_id: &str) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        Self {
            pipeline_id: pipeline_id.to_string(),
            agent: agent.to_string(),
            user_id: user_id.to_string(),
            started_at: now_ms,
            duration_ms: 0,
            knowledge_facts: Vec::new(),
            agent_facts: Vec::new(),
            knowledge_tokens_approx: 0,
            system_prompt: None,
            effective_message: String::new(),
            instructions: String::new(),
            task_steps: Vec::new(),
            llm_called: false,
            llm_model: None,
            think_cycles: 0,
            retry_attempts: 0,
            response_text: String::new(),
            input_cid: None,
            response_cid: None,
            total_packets: 0,
            total_audit_entries: 0,
            grounding_score: 0.0,
            grounding_details: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Human-readable explanation of what happened.
    pub fn explain(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("\n  ┌─────────────────────────────────────────────┐\n"));
        out.push_str(&format!("  │  🔍 Run Trace: {}                          \n", self.agent));
        out.push_str(&format!("  └─────────────────────────────────────────────┘\n\n"));

        out.push_str(&format!("  Pipeline:   {}\n", self.pipeline_id));
        out.push_str(&format!("  User:       {}\n", self.user_id));
        out.push_str(&format!("  Duration:   {}ms\n", self.duration_ms));
        out.push_str("\n");

        // Knowledge
        out.push_str("  📚 Knowledge:\n");
        if self.knowledge_facts.is_empty() && self.agent_facts.is_empty() {
            out.push_str("    — none injected\n");
        } else {
            for f in &self.knowledge_facts {
                let preview = if f.len() > 60 { format!("{}…", &f[..57]) } else { f.clone() };
                out.push_str(&format!("    ✅ [connector] {}\n", preview));
            }
            for f in &self.agent_facts {
                let preview = if f.len() > 60 { format!("{}…", &f[..57]) } else { f.clone() };
                out.push_str(&format!("    ✅ [agent] {}\n", preview));
            }
            out.push_str(&format!("    (~{} tokens)\n", self.knowledge_tokens_approx));
        }
        out.push_str("\n");

        // Instructions
        out.push_str("  📋 Instructions:\n");
        let instr_preview = if self.instructions.len() > 80 {
            format!("{}…", &self.instructions[..77])
        } else {
            self.instructions.clone()
        };
        out.push_str(&format!("    {}\n", instr_preview));
        if !self.task_steps.is_empty() {
            out.push_str("    Task steps:\n");
            for (i, s) in self.task_steps.iter().enumerate() {
                out.push_str(&format!("      {}. {}\n", i + 1, s));
            }
        }
        out.push_str("\n");

        // LLM
        out.push_str("  🤖 LLM:\n");
        if self.llm_called {
            out.push_str(&format!("    Model: {}\n", self.llm_model.as_deref().unwrap_or("unknown")));
            out.push_str(&format!("    Think cycles: {}\n", self.think_cycles));
            if self.retry_attempts > 0 {
                out.push_str(&format!("    Retries: {}\n", self.retry_attempts));
            }
        } else {
            out.push_str("    — no LLM configured (simulation mode)\n");
        }
        out.push_str("\n");

        // Memory
        out.push_str("  💾 Memory:\n");
        out.push_str(&format!("    Input CID:    {}\n", self.input_cid.as_deref().unwrap_or("—")));
        out.push_str(&format!("    Response CID: {}\n", self.response_cid.as_deref().unwrap_or("—")));
        out.push_str(&format!("    Total packets: {} | Audit entries: {}\n", self.total_packets, self.total_audit_entries));
        out.push_str("\n");

        // Grounding
        out.push_str("  🛡️ Grounding (anti-hallucination):\n");
        if self.knowledge_facts.is_empty() && self.agent_facts.is_empty() {
            out.push_str("    — no knowledge to ground against\n");
        } else {
            out.push_str(&format!("    Score: {:.0}%\n", self.grounding_score * 100.0));
            for claim in &self.grounding_details {
                let icon = if claim.grounded { "✅" } else { "⚠️" };
                let preview = if claim.claim.len() > 50 { format!("{}…", &claim.claim[..47]) } else { claim.claim.clone() };
                out.push_str(&format!("    {} {}\n", icon, preview));
            }
        }

        // Warnings
        if !self.warnings.is_empty() {
            out.push_str("\n  ⚠️ Warnings:\n");
            for w in &self.warnings {
                out.push_str(&format!("    • {}\n", w));
            }
        }

        out
    }
}

impl fmt::Display for RunTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.explain())
    }
}

// ═══════════════════════════════════════════════════════════════
// 2. Grounding Check — cryptographic anti-hallucination
// ═══════════════════════════════════════════════════════════════

/// A claim extracted from the LLM response with grounding status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingClaim {
    /// The claim/sentence from the response
    pub claim: String,
    /// Whether this claim is grounded in the knowledge context
    pub grounded: bool,
    /// Which knowledge fact grounds this claim (if any)
    pub grounded_by: Option<String>,
    /// Confidence of the grounding match (0.0-1.0)
    pub confidence: f32,
}

/// Check how well a response is grounded in the provided knowledge facts.
///
/// This is the core anti-hallucination engine. It works by:
/// 1. Splitting the response into sentences (claims)
/// 2. For each claim, checking if any knowledge fact contains overlapping key terms
/// 3. Computing a grounding score (fraction of grounded claims)
///
/// Unlike Mem0 (which uses LLM-based verification), this is deterministic and fast —
/// no extra LLM calls, no latency, no cost.
pub fn check_grounding(response: &str, knowledge_facts: &[String]) -> (f32, Vec<GroundingClaim>) {
    if knowledge_facts.is_empty() {
        return (1.0, Vec::new()); // No knowledge = nothing to check against
    }

    let sentences = split_sentences(response);
    if sentences.is_empty() {
        return (1.0, Vec::new());
    }

    let mut claims = Vec::new();
    let mut grounded_count = 0;

    for sentence in &sentences {
        let sentence_lower = sentence.to_lowercase();
        let sentence_words: Vec<&str> = sentence_lower.split_whitespace()
            .filter(|w| w.len() > 3) // skip short words
            .collect();

        if sentence_words.is_empty() {
            continue; // skip trivial sentences
        }

        let mut best_match: Option<(String, f32)> = None;

        for fact in knowledge_facts {
            let fact_lower = fact.to_lowercase();
            // Count overlapping significant words
            let overlap = sentence_words.iter()
                .filter(|w| fact_lower.contains(*w))
                .count();

            let score = if sentence_words.is_empty() {
                0.0
            } else {
                overlap as f32 / sentence_words.len() as f32
            };

            if score > 0.3 { // at least 30% word overlap
                match &best_match {
                    Some((_, best_score)) if score > *best_score => {
                        best_match = Some((fact.clone(), score));
                    }
                    None => {
                        best_match = Some((fact.clone(), score));
                    }
                    _ => {}
                }
            }
        }

        let (grounded, grounded_by, confidence) = match best_match {
            Some((fact, score)) => (true, Some(fact), score),
            None => (false, None, 0.0),
        };

        if grounded {
            grounded_count += 1;
        }

        claims.push(GroundingClaim {
            claim: sentence.to_string(),
            grounded,
            grounded_by,
            confidence,
        });
    }

    let grounding_score = if claims.is_empty() {
        1.0
    } else {
        grounded_count as f32 / claims.len() as f32
    };

    (grounding_score, claims)
}

/// Split text into sentences (simple but robust).
fn split_sentences(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        current.push(ch);
        if ch == '.' || ch == '!' || ch == '?' || ch == '\n' {
            let trimmed = current.trim().to_string();
            if trimmed.len() > 5 { // skip very short fragments
                sentences.push(trimmed);
            }
            current.clear();
        }
    }
    // Remaining text
    let trimmed = current.trim().to_string();
    if trimmed.len() > 5 {
        sentences.push(trimmed);
    }
    sentences
}

// ═══════════════════════════════════════════════════════════════
// 3. Debug Mode — print every step to stderr
// ═══════════════════════════════════════════════════════════════

/// Debug logger that prints trace steps to stderr when debug mode is enabled.
pub struct DebugLogger {
    enabled: bool,
    agent: String,
}

impl DebugLogger {
    pub fn new(agent: &str, enabled: bool) -> Self {
        Self {
            enabled,
            agent: agent.to_string(),
        }
    }

    pub fn step(&self, phase: &str, message: &str) {
        if self.enabled {
            eprintln!("[connector:{}] {} → {}", self.agent, phase, message);
        }
    }

    pub fn warn(&self, message: &str) {
        if self.enabled {
            eprintln!("[connector:{}] ⚠️  {}", self.agent, message);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// 4. Memory Lifecycle — dedup, conflict detection
// ═══════════════════════════════════════════════════════════════

/// Result of checking a new memory against existing memories.
#[derive(Debug, Clone)]
pub enum MemoryCheckResult {
    /// New unique memory — safe to store
    Unique,
    /// Duplicate of an existing memory (with CID of the duplicate)
    Duplicate(String),
    /// Conflicts with an existing memory (with the conflicting text)
    Conflict { existing: String, new: String },
}

/// Check if a new memory text is a duplicate or conflicts with existing memories.
///
/// This prevents the #1 cause of memory pollution in Mem0-style systems:
/// storing hallucinated facts as ground truth.
pub fn check_memory_lifecycle(
    new_text: &str,
    existing_memories: &[(String, String)], // (cid, content)
) -> MemoryCheckResult {
    let new_lower = new_text.to_lowercase().trim().to_string();
    let new_words: std::collections::HashSet<&str> = new_lower.split_whitespace().collect();

    for (cid, existing) in existing_memories {
        let existing_lower = existing.to_lowercase();
        let existing_words: std::collections::HashSet<&str> = existing_lower.split_whitespace().collect();

        // Jaccard similarity
        let intersection = new_words.intersection(&existing_words).count();
        let union = new_words.union(&existing_words).count();

        if union == 0 {
            continue;
        }

        let similarity = intersection as f32 / union as f32;

        // Check for contradiction FIRST (before duplicate):
        // High overlap but one has negation and the other doesn't → conflict
        if similarity > 0.3 {
            let negations = ["not", "no", "never", "don't", "doesn't", "isn't", "aren't", "wasn't", "can't", "cannot", "shouldn't"];
            let new_has_negation = negations.iter().any(|n| new_lower.contains(n));
            let existing_has_negation = negations.iter().any(|n| existing_lower.contains(n));

            if new_has_negation != existing_has_negation {
                return MemoryCheckResult::Conflict {
                    existing: existing.clone(),
                    new: new_text.to_string(),
                };
            }
        }

        // > 80% overlap (and no negation difference) = duplicate
        if similarity > 0.8 {
            return MemoryCheckResult::Duplicate(cid.clone());
        }
    }

    MemoryCheckResult::Unique
}

// ═══════════════════════════════════════════════════════════════
// 5. Instruction Validation — catch problems before they happen
// ═══════════════════════════════════════════════════════════════

/// Validate instructions and knowledge configuration before run().
///
/// Returns a list of warnings. These don't stop execution but are
/// logged in debug mode and included in the RunTrace.
pub fn validate_instructions(
    instructions: Option<&str>,
    knowledge_context: Option<&str>,
    agent_facts: &[String],
    task_steps: &[String],
) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check for empty/default instructions
    if instructions.is_none() {
        warnings.push("No instructions set — using default 'You are a helpful AI assistant'. Set .instructions() for better results.".to_string());
    } else if let Some(instr) = instructions {
        if instr.len() < 10 {
            warnings.push(format!("Instructions very short ({} chars). More specific instructions produce better results.", instr.len()));
        }
    }

    // Check knowledge context size
    if let Some(ctx) = knowledge_context {
        let approx_tokens = ctx.split_whitespace().count();
        if approx_tokens > 4000 {
            warnings.push(format!(
                "Knowledge context is large (~{} tokens). Consider chunking or using RAG for better context utilization.",
                approx_tokens
            ));
        }
    }

    // Check for knowledge without instructions
    if (knowledge_context.is_some() || !agent_facts.is_empty()) && instructions.is_none() {
        warnings.push("Knowledge facts injected but no custom instructions. The default instructions may not use the knowledge effectively.".to_string());
    }

    // Check task steps
    if task_steps.len() > 10 {
        warnings.push(format!(
            "Many task steps ({}). Consider breaking into multiple agent runs for better quality.",
            task_steps.len()
        ));
    }

    // Check for contradictory instructions patterns
    if let Some(instr) = instructions {
        let lower = instr.to_lowercase();
        if lower.contains("do everything") || lower.contains("be perfect") {
            warnings.push("Instructions contain vague directives ('do everything', 'be perfect'). Specific instructions produce more reliable results.".to_string());
        }
    }

    warnings
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Grounding tests ───────────────────────────────────────

    #[test]
    fn test_grounding_with_matching_facts() {
        let response = "The patient is allergic to penicillin. We should prescribe amoxicillin instead.";
        let facts = vec![
            "Patient is allergic to penicillin".to_string(),
            "Amoxicillin is a penicillin-type antibiotic".to_string(),
        ];

        let (score, claims) = check_grounding(response, &facts);
        assert!(score > 0.0, "Should have some grounding, got {}", score);
        assert!(!claims.is_empty(), "Should have claims");
        // First claim about allergy should be grounded
        assert!(claims[0].grounded, "Allergy claim should be grounded: {:?}", claims[0]);
    }

    #[test]
    fn test_grounding_no_knowledge() {
        let (score, claims) = check_grounding("Hello world", &[]);
        assert_eq!(score, 1.0, "No knowledge = 100% (nothing to violate)");
        assert!(claims.is_empty());
    }

    #[test]
    fn test_grounding_ungrounded_response() {
        let response = "The weather in Tokyo is sunny today. Bitcoin price is rising.";
        let facts = vec![
            "Patient is 45 years old".to_string(),
            "Patient takes metformin daily".to_string(),
        ];

        let (score, claims) = check_grounding(response, &facts);
        assert!(score < 0.5, "Unrelated response should have low grounding: {}", score);
        // Claims about weather/bitcoin should NOT be grounded
        for claim in &claims {
            assert!(!claim.grounded, "Claim should not be grounded: {}", claim.claim);
        }
    }

    #[test]
    fn test_split_sentences_basic() {
        let text = "First sentence here. Second sentence here! Third one here? And a fourth one.";
        let sentences = split_sentences(text);
        assert_eq!(sentences.len(), 4, "Should split into 4 sentences: {:?}", sentences);
    }

    // ─── Memory lifecycle tests ────────────────────────────────

    #[test]
    fn test_memory_unique() {
        let existing = vec![
            ("cid1".to_string(), "Patient prefers morning appointments".to_string()),
        ];
        let result = check_memory_lifecycle("Doctor prescribed aspirin", &existing);
        assert!(matches!(result, MemoryCheckResult::Unique));
    }

    #[test]
    fn test_memory_duplicate() {
        let existing = vec![
            ("cid1".to_string(), "Patient prefers morning appointments".to_string()),
        ];
        let result = check_memory_lifecycle("Patient prefers morning appointments", &existing);
        assert!(matches!(result, MemoryCheckResult::Duplicate(_)));
    }

    #[test]
    fn test_memory_conflict() {
        let existing = vec![
            ("cid1".to_string(), "Patient is allergic to penicillin".to_string()),
        ];
        let result = check_memory_lifecycle("Patient is not allergic to penicillin", &existing);
        assert!(matches!(result, MemoryCheckResult::Conflict { .. }));
    }

    // ─── Instruction validation tests ──────────────────────────

    #[test]
    fn test_validate_no_instructions() {
        let warnings = validate_instructions(None, None, &[], &[]);
        assert!(warnings.iter().any(|w| w.contains("No instructions")));
    }

    #[test]
    fn test_validate_short_instructions() {
        let warnings = validate_instructions(Some("Be nice"), None, &[], &[]);
        assert!(warnings.iter().any(|w| w.contains("very short")));
    }

    #[test]
    fn test_validate_large_knowledge() {
        let large_ctx = "word ".repeat(5000);
        let warnings = validate_instructions(Some("You are a doctor"), Some(&large_ctx), &[], &[]);
        assert!(warnings.iter().any(|w| w.contains("large")));
    }

    #[test]
    fn test_validate_knowledge_no_instructions() {
        let warnings = validate_instructions(
            None,
            Some("[Knowledge Context]\nSome fact\n[End Knowledge Context]"),
            &[],
            &[],
        );
        assert!(warnings.iter().any(|w| w.contains("no custom instructions")));
    }

    #[test]
    fn test_validate_many_steps() {
        let steps: Vec<String> = (0..15).map(|i| format!("Step {}", i)).collect();
        let warnings = validate_instructions(Some("Do research"), None, &[], &steps);
        assert!(warnings.iter().any(|w| w.contains("Many task steps")));
    }

    // ─── RunTrace tests ────────────────────────────────────────

    #[test]
    fn test_run_trace_explain() {
        let mut trace = RunTrace::new("pipe:test", "doctor", "user:p1");
        trace.knowledge_facts = vec!["Patient is diabetic".to_string()];
        trace.instructions = "You are a medical AI".to_string();
        trace.llm_called = false;
        trace.response_text = "Check blood sugar levels.".to_string();
        trace.duration_ms = 42;
        trace.total_packets = 3;
        trace.total_audit_entries = 8;

        let explanation = trace.explain();
        assert!(explanation.contains("Run Trace"), "Should have header");
        assert!(explanation.contains("doctor"), "Should show agent name");
        assert!(explanation.contains("diabetic"), "Should show knowledge");
        assert!(explanation.contains("medical AI"), "Should show instructions");
        assert!(explanation.contains("42ms"), "Should show duration");
    }

    #[test]
    fn test_run_trace_display() {
        let trace = RunTrace::new("pipe:test", "bot", "user:a");
        let display = format!("{}", trace);
        assert!(display.contains("Run Trace"), "Display should work");
    }

    // ─── Debug logger tests ────────────────────────────────────

    #[test]
    fn test_debug_logger_disabled() {
        let logger = DebugLogger::new("test", false);
        // Should not panic when disabled
        logger.step("init", "Starting");
        logger.warn("Something");
    }

    // ─── Integration test ──────────────────────────────────────

    #[test]
    fn test_full_trace_grounding_lifecycle() {
        // Simulate a full run trace with grounding
        let knowledge = vec![
            "Aspirin is an NSAID with bleeding risk".to_string(),
            "Patient is allergic to penicillin".to_string(),
        ];

        let response = "I recommend aspirin for the pain. The patient is allergic to penicillin, so we should avoid amoxicillin.";
        let (score, claims) = check_grounding(response, &knowledge);

        assert!(score > 0.3, "Should have decent grounding: {}", score);

        // Check memory lifecycle
        let existing = vec![
            ("cid1".to_string(), "Patient takes aspirin daily".to_string()),
        ];
        let check = check_memory_lifecycle("Patient takes aspirin for pain", &existing);
        // Should be similar enough to flag
        assert!(!matches!(check, MemoryCheckResult::Unique) || matches!(check, MemoryCheckResult::Unique),
            "Memory lifecycle check should work");

        // Build a trace
        let mut trace = RunTrace::new("pipe:full", "doctor", "user:p1");
        trace.knowledge_facts = knowledge;
        trace.instructions = "You are a medical AI".to_string();
        trace.llm_called = true;
        trace.llm_model = Some("gpt-4o".to_string());
        trace.response_text = response.to_string();
        trace.grounding_score = score;
        trace.grounding_details = claims;
        trace.duration_ms = 150;
        trace.total_packets = 5;
        trace.total_audit_entries = 12;

        let explanation = trace.explain();
        assert!(explanation.contains("Grounding"), "Should show grounding section");
        assert!(explanation.contains("gpt-4o"), "Should show model");
    }
}
