//! # Connector Engine Prelude
//!
//! A convenience module that re-exports the most commonly used types and traits.
//!
//! ## Quick Start (3 lines)
//!
//! ```rust
//! use connector_engine::prelude::*;
//!
//! let agent = Agent::new("my-bot", "You are helpful");
//! let result = agent.run("Hello!").await?;
//! println!("{}", result.text());
//! ```
//!
//! ## With Memory (5 lines)
//!
//! ```rust
//! use connector_engine::prelude::*;
//!
//! let agent = Agent::new("my-bot", "You are helpful");
//! agent.remember("User prefers dark mode").await?;
//! let result = agent.run("What do you know about me?").await?;
//! ```
//!
//! ## With Tools (10 lines)
//!
//! ```rust
//! use connector_engine::prelude::*;
//!
//! let search = tool("search", |query: String| async move {
//!     Ok(format!("Results for: {}", query))
//! });
//!
//! let agent = Agent::builder("research")
//!     .instructions("You help with research")
//!     .tool(search)
//!     .build();
//! ```
//!
//! ## With Compliance (15 lines)
//!
//! ```rust
//! use connector_engine::prelude::*;
//!
//! let agent = Agent::builder("medical")
//!     .instructions("You are a triage nurse")
//!     .comply(&["hipaa", "phi", "audit"])
//!     .build();
//!
//! let result = agent.run("Patient reports chest pain").await?;
//! println!("Trust: {}/100", result.trust_score());
//! println!("Compliance: {:?}", result.compliance());
//! ```

// ═══════════════════════════════════════════════════════════════════════════════
// CORE TYPES — Most commonly used
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::error::EngineError;
pub use crate::output::{PipelineOutput, PipelineResult};
pub use crate::trust::{TrustComputer, TrustScore, TrustDimensions};
pub use crate::trace::{Trace, TraceBuilder, Span, SpanType};

// ═══════════════════════════════════════════════════════════════════════════════
// TOOLS & ACTIONS — Building agent capabilities
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::tool_def::{Tool, ToolBuilder, ToolParam, ParamType, ToolResult};
pub use crate::action::{Action, ActionBuilder, ActionResult, ActionContext};

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY & KNOWLEDGE — Agent memory system
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::memory::{MemoryCoordinator, KnowledgeCoordinator, PacketSummary};
pub use crate::memory_format::ConnectorMemory;
pub use crate::knowledge::{KnowledgeEngine, IngestResult, CompiledKnowledge};
pub use crate::rag::{RagEngine, RetrievalContext, RetrievedFact};

// ═══════════════════════════════════════════════════════════════════════════════
// COGNITIVE — Agent reasoning
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::perception::{PerceptionEngine, Observation, PerceivedContext};
pub use crate::logic::{LogicEngine, Plan, PlanStep, ReasoningChain};
pub use crate::binding::{BindingEngine, CognitivePhase, CycleSummary};

// ═══════════════════════════════════════════════════════════════════════════════
// SAFETY & COMPLIANCE — Enterprise features
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::claims::{Claim, ClaimSet, ClaimVerifier, VerificationResult};
pub use crate::grounding::{GroundingTable, CodeEntry};
pub use crate::judgment::{JudgmentEngine, JudgmentResult};
pub use crate::aapi::{ActionEngine, PolicyDecision, ActionPolicy};
pub use crate::compliance::ComplianceConfig;

// ═══════════════════════════════════════════════════════════════════════════════
// BOOKS — Double-entry accounting for AI operations
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::books::{
    JournalEntry, AccountId, AccountClass, LedgerAction, Outcome, VerificationTier,
    JournalBus, JournalQuery, JournalQueryResult,
    accounts, post,
};

// ═══════════════════════════════════════════════════════════════════════════════
// KERNEL OPS — Low-level kernel operations
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::kernel_ops::{KernelOps, KernelStats, AgentInfo, AuditEntry};

// ═══════════════════════════════════════════════════════════════════════════════
// COGNITIVE SUBSTRATE — Advanced cognitive architecture
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::cognitive::{
    CognitiveSubstrate, CognitiveContext, ThoughtRecord,
    Tension, TensionGraph, Possibility, Commitment,
    ExpertiseKernel, ExpertiseRegistry,
};

// ═══════════════════════════════════════════════════════════════════════════════
// CNP — Connector Native Protocol
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::cnp::{
    CnpStack, CnpMessage, CnpPayload, CnpSession,
    CnpPort, CnpRouter,
};

// ═══════════════════════════════════════════════════════════════════════════════
// CLS — Contract Language System
// ═══════════════════════════════════════════════════════════════════════════════

pub use crate::cls::{
    SolutionContract, ContractIR, ContractNode,
    compile_ccl, compile_ccl_default,
};

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE TYPES — Type aliases for common patterns
// ═══════════════════════════════════════════════════════════════════════════════

/// Result type for engine operations
pub type EngineResult<T> = Result<T, EngineError>;

/// Result type for async operations
pub type AsyncResult<T> = std::pin::Pin<Box<dyn std::future::Future<Output = EngineResult<T>> + Send>>;

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTIONS — Quick builders
// ═══════════════════════════════════════════════════════════════════════════════

/// Create a new tool with the given name and handler.
///
/// # Example
///
/// ```rust
/// use connector_engine::prelude::*;
///
/// let search = tool("search")
///     .description("Search the web")
///     .param("query", ParamType::String)
///     .build();
/// ```
pub fn tool(name: &str) -> ToolBuilder {
    ToolBuilder::new(name)
}

/// Create a new action with the given name.
///
/// # Example
///
/// ```rust
/// use connector_engine::prelude::*;
///
/// let send_email = action("send_email")
///     .description("Send an email")
///     .param("to", ParamType::String)
///     .param("subject", ParamType::String)
///     .param("body", ParamType::String)
///     .build();
/// ```
pub fn action(name: &str) -> ActionBuilder {
    ActionBuilder::new(name)
}

/// Create a new journal entry for the books ledger.
///
/// # Example
///
/// ```rust
/// use connector_engine::prelude::*;
///
/// let entry = journal("agent:bot", "Processed user request")
///     .debit(accounts::tokens_used(), 150)
///     .credit(accounts::tokens_available(), 150)
///     .build()?;
/// ```
pub fn journal(actor: &str, description: &str) -> JournalEntryBuilder {
    JournalEntryBuilder::new(actor, description)
}

/// Create a new trace for observability.
///
/// # Example
///
/// ```rust
/// use connector_engine::prelude::*;
///
/// let trace = trace("agent:bot", "process_request")
///     .span("parse_input", SpanType::Parse)
///     .span("call_llm", SpanType::LlmCall)
///     .span("format_output", SpanType::Format)
///     .build();
/// ```
pub fn trace(agent: &str, operation: &str) -> TraceBuilder {
    TraceBuilder::new(agent, operation)
}

// ═══════════════════════════════════════════════════════════════════════════════
// JOURNAL ENTRY BUILDER — Simplified books ledger entry creation
// ═══════════════════════════════════════════════════════════════════════════════

/// Builder for creating journal entries with a fluent API.
pub struct JournalEntryBuilder {
    actor: String,
    description: String,
    debits: Vec<(AccountId, i64)>,
    credits: Vec<(AccountId, i64)>,
    tier: VerificationTier,
}

impl JournalEntryBuilder {
    /// Create a new journal entry builder.
    pub fn new(actor: &str, description: &str) -> Self {
        Self {
            actor: actor.to_string(),
            description: description.to_string(),
            debits: Vec::new(),
            credits: Vec::new(),
            tier: VerificationTier::Unverified,
        }
    }

    /// Add a debit line to the entry.
    pub fn debit(mut self, account: AccountId, amount: i64) -> Self {
        self.debits.push((account, amount));
        self
    }

    /// Add a credit line to the entry.
    pub fn credit(mut self, account: AccountId, amount: i64) -> Self {
        self.credits.push((account, amount));
        self
    }

    /// Set the verification tier.
    pub fn tier(mut self, tier: VerificationTier) -> Self {
        self.tier = tier;
        self
    }

    /// Build the journal entry.
    pub fn build(self) -> EngineResult<JournalEntry> {
        // Use the quick constructor and builder pattern
        let action = if !self.debits.is_empty() {
            LedgerAction::MemoryDeposit
        } else {
            LedgerAction::AccountOpened
        };
        
        let mut entry = JournalEntry::quick(&self.actor, action, Outcome::Cleared)
            .with_description(&self.description);
        
        // Set quantity from first debit if available
        if let Some((_, amount)) = self.debits.first() {
            entry = entry.with_quantity(*amount as f64, "count");
        }
        
        Ok(entry)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGENT RESULT — Rich result object with progressive disclosure
// ═══════════════════════════════════════════════════════════════════════════════

/// Rich result object from agent operations.
///
/// Provides easy access to response text and advanced capabilities
/// like trust scoring, books ledger, and compliance reports.
///
/// # Example
///
/// ```rust
/// let result = agent.run("Hello!").await?;
/// println!("{}", result.text());       // "Hello! How can I help?"
/// println!("{}", result.tokens());     // 150
/// println!("{}", result.trust());      // 0.95
/// println!("{}", result.cost_usd());   // 0.002
/// ```
#[derive(Debug, Clone)]
pub struct AgentResult {
    /// The agent's response text
    pub text: String,
    /// Total tokens used (input + output)
    pub tokens: u64,
    /// Response latency in milliseconds
    pub latency_ms: u64,
    /// Estimated cost in USD
    pub cost_usd: f64,
    /// Whether the request succeeded
    pub ok: bool,
    /// Trust score (0.0 - 1.0)
    pub trust: f64,
    /// Trust grade (A+, A, B, C, D, F)
    pub trust_grade: String,
    /// Trace ID for debugging
    pub trace_id: Option<String>,
    /// Tool calls made during this run
    pub tool_calls: Vec<ToolCallRecord>,
    /// Compliance report (if enabled)
    pub compliance: Option<ComplianceReport>,
    /// Books ledger entry
    pub books_entry: Option<JournalEntry>,
}

impl AgentResult {
    /// Get the response text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Get the total tokens used.
    pub fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Get the trust score (0.0 - 1.0).
    pub fn trust(&self) -> f64 {
        self.trust
    }

    /// Get the trust score as a percentage (0 - 100).
    pub fn trust_score(&self) -> u8 {
        (self.trust * 100.0) as u8
    }

    /// Get the trust grade.
    pub fn trust_grade(&self) -> &str {
        &self.trust_grade
    }

    /// Check if the run succeeded.
    pub fn is_success(&self) -> bool {
        self.ok
    }

    /// Check if the run failed.
    pub fn is_failure(&self) -> bool {
        !self.ok
    }

    /// Get the compliance report (if enabled).
    pub fn compliance(&self) -> Option<&ComplianceReport> {
        self.compliance.as_ref()
    }

    /// Get the books ledger entry.
    pub fn books_entry(&self) -> Option<&JournalEntry> {
        self.books_entry.as_ref()
    }

    /// Get documentation URL for a topic.
    pub fn learn_more(&self, topic: &str) -> String {
        format!("https://docs.connector.dev/capabilities/{}", topic)
    }
}

impl std::fmt::Display for AgentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "┌{}┐", "─".repeat(58))?;
        writeln!(f, "│ Agent Response{:>43}│", "")?;
        writeln!(f, "├{}┤", "─".repeat(58))?;
        
        let text_preview = if self.text.len() > 45 {
            format!("{}...", &self.text[..45])
        } else {
            self.text.clone()
        };
        writeln!(f, "│ Text:    {:<48}│", text_preview)?;
        writeln!(f, "│ Tokens:  {:<48}│", self.tokens)?;
        writeln!(f, "│ Cost:    ${:<47.4}│", self.cost_usd)?;
        writeln!(f, "│ Trust:   {}/100 (Grade: {}){:>30}│", 
            self.trust_score(), self.trust_grade, "")?;
        
        if let Some(ref trace_id) = self.trace_id {
            writeln!(f, "│ Trace:   {:<48}│", trace_id)?;
        }
        
        writeln!(f, "└{}┘", "─".repeat(58))
    }
}

/// Record of a tool call made during agent execution.
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    /// Tool name
    pub name: String,
    /// Tool arguments
    pub arguments: serde_json::Value,
    /// Tool result
    pub result: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Compliance report for an agent operation.
#[derive(Debug, Clone)]
pub struct ComplianceReport {
    /// Frameworks checked
    pub frameworks: Vec<String>,
    /// Whether all checks passed
    pub passed: bool,
    /// Individual check results
    pub checks: Vec<ComplianceCheck>,
}

/// Individual compliance check result.
#[derive(Debug, Clone)]
pub struct ComplianceCheck {
    /// Framework name
    pub framework: String,
    /// Check name
    pub check: String,
    /// Whether the check passed
    pub passed: bool,
    /// Details or reason for failure
    pub details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_result_display() {
        let result = AgentResult {
            text: "Hello! How can I help you today?".to_string(),
            tokens: 150,
            latency_ms: 250,
            cost_usd: 0.002,
            ok: true,
            trust: 0.95,
            trust_grade: "A+".to_string(),
            trace_id: Some("trace-abc123".to_string()),
            tool_calls: vec![],
            compliance: None,
            books_entry: None,
        };

        let display = format!("{}", result);
        assert!(display.contains("Agent Response"));
        assert!(display.contains("Hello!"));
        assert!(display.contains("150"));
        assert!(display.contains("95/100"));
        assert!(display.contains("A+"));
    }

    #[test]
    fn test_agent_result_methods() {
        let result = AgentResult {
            text: "Test response".to_string(),
            tokens: 100,
            latency_ms: 200,
            cost_usd: 0.001,
            ok: true,
            trust: 0.85,
            trust_grade: "B".to_string(),
            trace_id: None,
            tool_calls: vec![],
            compliance: None,
            books_entry: None,
        };

        assert_eq!(result.text(), "Test response");
        assert_eq!(result.tokens(), 100);
        assert_eq!(result.trust(), 0.85);
        assert_eq!(result.trust_score(), 85);
        assert_eq!(result.trust_grade(), "B");
        assert!(result.is_success());
        assert!(!result.is_failure());
    }

    #[test]
    fn test_journal_entry_builder() {
        let builder = journal("agent:test", "Test entry")
            .debit(accounts::tokens_used(), 100)
            .credit(accounts::tokens_available(), 100)
            .tier(VerificationTier::T1);

        // Builder should be constructable
        assert_eq!(builder.actor, "agent:test");
        assert_eq!(builder.description, "Test entry");
        assert_eq!(builder.debits.len(), 1);
        assert_eq!(builder.credits.len(), 1);
    }
}
