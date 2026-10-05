//! # ConnectorMap Books — Accounting-Inspired Operational Ledger
//!
//! Transforms raw kernel audit entries into a journal-ledger-statement model.
//! Every agent action becomes a transaction with debit/credit posting lines.
//!
//! ## Source of Truth Layers
//!
//! | Tier | Name | Description | Trust Level |
//! |------|------|-------------|-------------|
//! | **T0** | Notarized | Kernel HMAC audit chain | Authoritative, append-only, tamper-evident |
//! | **T1** | Recorded | Engine store audit log | May lag by flush interval |
//! | **T2** | Derived | Computed projections | Statements, costs, trust scores |
//! | **T3** | Rendered | CLI/API output | Ephemeral, for display only |
//!
//! ## Core Abstractions
//!
//! - [`JournalEntry`]: Single transaction in the general journal (double-entry)
//! - [`AccountId`]: Canonical account identifier (`agent:pid:000003`, `ns:research`, `tool:web_search`)
//! - [`LedgerLine`]: One side of a double-entry posting (debit or credit)
//! - [`LedgerAction`]: The verb of every journal entry (mapped from `MemoryKernelOp`)
//! - [`AccountLedger`]: Per-account view with running totals
//! - [`AccountStatement`]: Full investigation view with all positions
//! - [`SystemPosition`]: Overall system state report
//! - [`ReconciliationReport`]: T0 vs T1 verification result
//!
//! ## Chart of Accounts
//!
//! The [`accounts`] module defines account codes following accounting conventions:
//! - **1xxx**: Assets (active memory, agents, sessions, capabilities)
//! - **2xxx**: Liabilities (pending approvals, escrow holds)
//! - **3xxx**: Operations (memory ops, tool calls, access events)
//! - **4xxx**: Cost Centers (tokens, compute time, dollar cost)
//! - **5xxx**: Value Produced (completed pipelines, knowledge created)
//! - **9xxx**: Control (HMAC chain, SCITT receipts, reconciliation)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use connector_engine::books::prelude::*;
//!
//! // Create a journal entry in one line
//! let entry = JournalEntry::quick("agent:my-agent", Action::ToolDispatched, Outcome::Cleared)
//!     .with_target(AccountId::tool("web_search"))
//!     .with_quantity(150.0, "ms")
//!     .with_description("Search for weather data");
//!
//! // Quick queries
//! let last_10 = JournalQuery::last(10);
//! let agent_entries = JournalQuery::for_agent("agent:my-agent");
//! let failures = JournalQuery::failures();
//!
//! // Check outcomes easily
//! if entry.is_success() {
//!     println!("{} Entry cleared!", entry.outcome.emoji());
//! }
//!
//! // Subscribe to real-time entries
//! let bus = JournalBus::new();
//! let mut rx = bus.subscribe();
//! ```
//!
//! ## Common Patterns
//!
//! ```rust,no_run
//! use connector_engine::books::prelude::*;
//!
//! // Parse account IDs safely
//! let acc = AccountId::parse_or_system("agent:test"); // Never fails
//!
//! // Filter by action type
//! let action = Action::ToolDispatched;
//! if action.is_tool() {
//!     println!("Tool action: {}", action.short_name());
//! }
//!
//! // Build complex queries fluently
//! let query = JournalQuery::new()
//!     .actor("agent:research")
//!     .action(Action::MemoryDeposit)
//!     .since(1709251200000)
//!     .limit(50);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use vac_core::types::{KernelAuditEntry, MemoryKernelOp, OpOutcome};

use crate::engine_store::EngineAuditEntry;

// ═══════════════════════════════════════════════════════════════════════════
// PRELUDE — Import everything you need with `use books::prelude::*`
// ═══════════════════════════════════════════════════════════════════════════

/// Prelude module for convenient imports.
///
/// ```rust,ignore
/// use connector_engine::books::prelude::*;
///
/// // Now you have access to all common types
/// let entry = JournalEntry::quick("agent:test", LedgerAction::ToolDispatched, Outcome::Cleared);
/// ```
pub mod prelude {
    pub use super::{
        // Core types
        JournalEntry, AccountId, LedgerLine, LedgerAction, Outcome, VerificationTier,
        // Ledger & statements
        AccountLedger, AccountStatement, LedgerTotals,
        // System reports
        SystemPosition, ReconciliationReport,
        // Query
        JournalQuery, JournalQueryResult,
        // Bus
        JournalBus,
        // Errors
        JournalEntryError,
        // Account codes
        accounts,
    };
    
    /// Type alias for common action type
    pub type Action = super::LedgerAction;
}

// ═══════════════════════════════════════════════════════════════════════════
// CHART OF ACCOUNTS — Classification codes for all ledger postings
// ═══════════════════════════════════════════════════════════════════════════

pub mod accounts {
    // 1000 ASSETS (what the system holds)
    pub const ACTIVE_MEMORY: &str = "1110";
    pub const SEALED_MEMORY: &str = "1120";
    pub const SHARED_MEMORY: &str = "1130";
    pub const RUNNING_AGENTS: &str = "1210";
    pub const AGENT_CAPABILITIES: &str = "1220";
    pub const ACTIVE_SESSIONS: &str = "1230";
    pub const KNOWLEDGE_ENTITIES: &str = "1310";
    pub const KNOWLEDGE_SETS: &str = "1320";

    // 2000 LIABILITIES (pending obligations)
    pub const PENDING_APPROVALS: &str = "2100";
    pub const PENDING_TOOL_RESULTS: &str = "2200";
    pub const ESCROW_HOLDS: &str = "2300";

    // 3000 OPERATIONS (activity accounts)
    pub const MEMORY_DEPOSITS: &str = "3110";
    pub const MEMORY_WITHDRAWALS: &str = "3120";
    pub const MEMORY_MAINTENANCE: &str = "3130";
    pub const TOOL_CALLS: &str = "3210";
    pub const MCP_BRIDGE_CALLS: &str = "3220";
    pub const INTER_AGENT_MESSAGES: &str = "3230";
    pub const ACCESS_GRANTS: &str = "3310";
    pub const ACCESS_DENIALS: &str = "3320";
    pub const POLICY_CHECKS: &str = "3330";
    pub const REGISTRATIONS: &str = "3410";
    pub const STARTS_RESUMES: &str = "3420";
    pub const PAUSES_SUSPENSIONS: &str = "3430";
    pub const TERMINATIONS: &str = "3440";

    // 4000 COST CENTER (what was spent)
    pub const INPUT_TOKENS: &str = "4110";
    pub const OUTPUT_TOKENS: &str = "4120";
    pub const LLM_COMPUTE_TIME: &str = "4210";
    pub const TOOL_EXEC_TIME: &str = "4220";
    pub const DOLLAR_COST: &str = "4300";

    // 5000 VALUE PRODUCED
    pub const COMPLETED_PIPELINES: &str = "5100";
    pub const SUCCESSFUL_TOOL_RESULTS: &str = "5200";
    pub const KNOWLEDGE_CREATED: &str = "5300";

    // 9000 CONTROL (integrity accounts)
    pub const HMAC_CHAIN: &str = "9100";
    pub const SCITT_RECEIPTS: &str = "9200";
    pub const MERKLE_CHECKPOINTS: &str = "9300";
    pub const RECONCILIATION_RESULTS: &str = "9400";

    /// Get human-readable label for an account code
    pub fn label(code: &str) -> &'static str {
        match code {
            "1110" => "Active Memory",
            "1120" => "Sealed Memory",
            "1130" => "Shared Memory",
            "1210" => "Running Agents",
            "1220" => "Agent Capabilities",
            "1230" => "Active Sessions",
            "1310" => "Knowledge Entities",
            "1320" => "Knowledge Sets",
            "2100" => "Pending Approvals",
            "2200" => "Pending Tool Results",
            "2300" => "Escrow Holds",
            "3110" => "Memory Deposits",
            "3120" => "Memory Withdrawals",
            "3130" => "Memory Maintenance",
            "3210" => "Tool Calls",
            "3220" => "MCP Bridge Calls",
            "3230" => "Inter-Agent Messages",
            "3310" => "Access Grants",
            "3320" => "Access Denials",
            "3330" => "Policy Checks",
            "3410" => "Registrations",
            "3420" => "Starts/Resumes",
            "3430" => "Pauses/Suspensions",
            "3440" => "Terminations",
            "4110" => "Input Tokens",
            "4120" => "Output Tokens",
            "4210" => "LLM Compute Time",
            "4220" => "Tool Exec Time",
            "4300" => "Dollar Cost",
            "5100" => "Completed Pipelines",
            "5200" => "Successful Tool Results",
            "5300" => "Knowledge Created",
            "9100" => "HMAC Chain",
            "9200" => "SCITT Receipts",
            "9300" => "Merkle Checkpoints",
            "9400" => "Reconciliation Results",
            _ => "Unknown Account",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CORE TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// Canonical account identifier with strict format.
///
/// Account IDs follow the pattern `{class}:{identifier}` where class is one of:
/// - `agent` — Agent process (e.g., `agent:pid:000003`)
/// - `ns` — Memory namespace (e.g., `ns:research`)
/// - `tool` — Tool identifier (e.g., `tool:web_search`)
/// - `session` — Session identifier (e.g., `session:sess:001`)
/// - `model` — LLM model (e.g., `model:gpt-4`)
/// - `system` — System component (e.g., `system:kernel`)
///
/// # Examples
///
/// ```rust
/// use connector_engine::books::AccountId;
///
/// let agent = AccountId::agent("pid:000003", "research_agent");
/// assert_eq!(agent.id, "agent:pid:000003");
///
/// let parsed = AccountId::parse("ns:research").unwrap();
/// assert_eq!(parsed.display_name, "research");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AccountId {
    /// Account class (Agent, Namespace, Tool, etc.)
    pub class: AccountClass,
    /// Full canonical identifier (e.g., `agent:pid:000003`)
    pub id: String,
    /// Human-readable display name
    pub display_name: String,
}

impl AccountId {
    /// Create an agent account ID.
    /// 
    /// ```rust
    /// use connector_engine::books::AccountId;
    /// let acc = AccountId::agent("pid:000003", "research_agent");
    /// ```
    pub fn agent(pid: &str, display_name: &str) -> Self {
        Self {
            class: AccountClass::Agent,
            id: format!("agent:{}", pid),
            display_name: display_name.to_string(),
        }
    }

    /// Create a namespace account ID.
    pub fn namespace(name: &str) -> Self {
        Self {
            class: AccountClass::Namespace,
            id: format!("ns:{}", name),
            display_name: name.to_string(),
        }
    }

    /// Create a tool account ID.
    pub fn tool(name: &str) -> Self {
        Self {
            class: AccountClass::Tool,
            id: format!("tool:{}", name),
            display_name: name.to_string(),
        }
    }

    /// Create a session account ID.
    pub fn session(id: &str) -> Self {
        Self {
            class: AccountClass::Session,
            id: format!("session:{}", id),
            display_name: id.to_string(),
        }
    }

    /// Create a model account ID.
    pub fn model(name: &str) -> Self {
        Self {
            class: AccountClass::Model,
            id: format!("model:{}", name),
            display_name: name.to_string(),
        }
    }

    /// Create a system account ID.
    pub fn system(component: &str) -> Self {
        Self {
            class: AccountClass::System,
            id: format!("system:{}", component),
            display_name: component.to_string(),
        }
    }

    /// Parse from canonical string format (e.g., "agent:pid:000003").
    /// Returns `None` if the format is invalid.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        let (class_str, rest) = (parts[0], parts[1]);
        let class = match class_str {
            "agent" => AccountClass::Agent,
            "ns" => AccountClass::Namespace,
            "tool" => AccountClass::Tool,
            "session" => AccountClass::Session,
            "model" => AccountClass::Model,
            "system" => AccountClass::System,
            _ => return None,
        };
        Some(Self {
            class,
            id: s.to_string(),
            display_name: rest.to_string(),
        })
    }

    /// Quick parse that returns a default system account on failure.
    /// Use when you need an AccountId but don't want to handle Option.
    pub fn parse_or_system(s: &str) -> Self {
        Self::parse(s).unwrap_or_else(|| Self::system("unknown"))
    }

    /// Check if this is an agent account.
    pub fn is_agent(&self) -> bool {
        matches!(self.class, AccountClass::Agent)
    }

    /// Check if this is a system account.
    pub fn is_system(&self) -> bool {
        matches!(self.class, AccountClass::System)
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AccountClass {
    Agent,
    Namespace,
    Tool,
    Session,
    Model,
    System,
}

/// One side of a double-entry ledger posting.
///
/// Every [`JournalEntry`] has exactly one debit line and one credit line.
/// The debit represents what was consumed/left, the credit represents what was produced/entered.
///
/// # Account Codes
///
/// Account codes follow the [`accounts`] module conventions:
/// - `1xxx` — Assets
/// - `2xxx` — Liabilities
/// - `3xxx` — Operations
/// - `4xxx` — Cost Centers
/// - `5xxx` — Value Produced
/// - `9xxx` — Control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerLine {
    /// Account code from Chart of Accounts (e.g., `"1110"` for Active Memory)
    pub account_code: String,
    /// Human-readable account label (e.g., `"Active Memory"`)
    pub account_label: String,
    /// Quantity posted (bytes, tokens, count, etc.)
    pub amount: f64,
    /// Unit of measurement (`"bytes"`, `"tokens"`, `"ms"`, `"count"`)
    pub unit: String,
    /// Optional reference (CID, tool name, namespace, etc.)
    pub reference: Option<String>,
}

impl LedgerLine {
    pub fn new(account_code: &str, amount: f64, unit: &str, reference: Option<String>) -> Self {
        Self {
            account_code: account_code.to_string(),
            account_label: accounts::label(account_code).to_string(),
            amount,
            unit: unit.to_string(),
            reference,
        }
    }

    pub fn zero(account_code: &str) -> Self {
        Self::new(account_code, 0.0, "count", None)
    }
}

/// Transaction outcome — the result of a journal entry.
///
/// Maps from kernel [`OpOutcome`] to accounting terminology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Outcome {
    /// Transaction completed successfully (maps from `OpOutcome::Success`)
    Cleared,
    /// Transaction denied by access control or policy (maps from `OpOutcome::Denied`)
    Rejected,
    /// Transaction failed due to runtime error (maps from `OpOutcome::Failed`)
    Failed,
    /// Transaction awaiting async approval (maps from `OpOutcome::Pending`)
    Pending,
    /// Transaction was a no-op or skipped (maps from `OpOutcome::Skipped`)
    Voided,
}

impl Outcome {
    /// Check if this is a successful outcome
    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Cleared)
    }

    /// Check if this is a failure outcome
    pub fn is_err(&self) -> bool {
        matches!(self, Outcome::Failed | Outcome::Rejected)
    }

    /// Get a short display string
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Cleared => "cleared",
            Outcome::Rejected => "rejected",
            Outcome::Failed => "failed",
            Outcome::Pending => "pending",
            Outcome::Voided => "voided",
        }
    }

    /// Get an emoji for display
    pub fn emoji(&self) -> &'static str {
        match self {
            Outcome::Cleared => "\u{2705}",  // checkmark
            Outcome::Rejected => "\u{274C}", // x
            Outcome::Failed => "\u{26A0}",   // warning
            Outcome::Pending => "\u{23F3}",  // hourglass
            Outcome::Voided => "\u{2B55}",   // circle
        }
    }
}

impl From<&OpOutcome> for Outcome {
    fn from(op: &OpOutcome) -> Self {
        match op {
            OpOutcome::Success => Outcome::Cleared,
            OpOutcome::Denied => Outcome::Rejected,
            OpOutcome::Failed => Outcome::Failed,
            OpOutcome::Skipped => Outcome::Voided,
            OpOutcome::Pending => Outcome::Pending,
        }
    }
}

/// Verification tier — indicates the trust level of a journal entry.
///
/// Higher tiers (lower numbers) have stronger integrity guarantees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationTier {
    /// **T0**: Kernel HMAC chain — tamper-evident, hash-linked, authoritative
    Notarized,
    /// **T1**: Engine store — sequential, recorded, may lag kernel
    Recorded,
    /// **T2**: Platform-computed — derived from T0/T1, computed projections
    Derived,
    /// **T3**: User-provided — unverified external input, display only
    Unverified,
}

impl VerificationTier {
    /// Returns the tier number (0-3, lower is more trusted)
    pub fn tier_number(&self) -> u8 {
        match self {
            VerificationTier::Notarized => 0,
            VerificationTier::Recorded => 1,
            VerificationTier::Derived => 2,
            VerificationTier::Unverified => 3,
        }
    }

    /// Returns true if this tier is authoritative (T0)
    pub fn is_authoritative(&self) -> bool {
        matches!(self, VerificationTier::Notarized)
    }

    /// Returns the tier name as a string
    pub fn name(&self) -> &'static str {
        match self {
            VerificationTier::Notarized => "T0 Notarized",
            VerificationTier::Recorded => "T1 Recorded",
            VerificationTier::Derived => "T2 Derived",
            VerificationTier::Unverified => "T3 Unverified",
        }
    }
}

/// Ledger action — the verb of every journal entry.
/// Mapped from MemoryKernelOp but expressed in ledger terms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LedgerAction {
    AccountOpened,
    AccountActivated,
    AccountSuspended,
    AccountResumed,
    AccountClosed,
    MemoryDeposit,
    MemoryWithdrawal,
    MemoryEviction,
    MemoryPromotion,
    MemoryDemotion,
    MemoryCleared,
    MemorySealed,
    SessionOpened,
    SessionClosed,
    SessionCompressed,
    ContextSaved,
    ContextRestored,
    AccessGranted,
    AccessRevoked,
    AccessChecked,
    ToolDispatched,
    SignalSent,
    HandlerRegistered,
    BudgetSet,
    TokensCharged,
    ComputeCharged,
    LlmScheduled,
    LlmDequeued,
    MessageSent,
    MessageReceived,
    ChannelOpened,
    ChannelClosed,
    PolicyChecked,
    IntegrityChecked,
    MaintenanceRun,
    BridgeRegistered,
    BridgeInvoked,
    IdentityRegistered,
    CardPublished,
    ContextUpdated,
}

impl LedgerAction {
    /// Map from MemoryKernelOp to LedgerAction
    pub fn from_kernel_op(op: &MemoryKernelOp) -> Self {
        match op {
            MemoryKernelOp::AgentRegister => LedgerAction::AccountOpened,
            MemoryKernelOp::AgentStart => LedgerAction::AccountActivated,
            MemoryKernelOp::AgentSuspend => LedgerAction::AccountSuspended,
            MemoryKernelOp::AgentResume => LedgerAction::AccountResumed,
            MemoryKernelOp::AgentTerminate => LedgerAction::AccountClosed,
            MemoryKernelOp::MemAlloc => LedgerAction::MemoryDeposit,
            MemoryKernelOp::MemWrite => LedgerAction::MemoryDeposit,
            MemoryKernelOp::MemRead => LedgerAction::MemoryWithdrawal,
            MemoryKernelOp::MemEvict => LedgerAction::MemoryEviction,
            MemoryKernelOp::MemPromote => LedgerAction::MemoryPromotion,
            MemoryKernelOp::MemDemote => LedgerAction::MemoryDemotion,
            MemoryKernelOp::MemClear => LedgerAction::MemoryCleared,
            MemoryKernelOp::MemSeal => LedgerAction::MemorySealed,
            MemoryKernelOp::SessionCreate => LedgerAction::SessionOpened,
            MemoryKernelOp::SessionClose => LedgerAction::SessionClosed,
            MemoryKernelOp::SessionCompress => LedgerAction::SessionCompressed,
            MemoryKernelOp::ContextSnapshot => LedgerAction::ContextSaved,
            MemoryKernelOp::ContextRestore => LedgerAction::ContextRestored,
            MemoryKernelOp::AccessGrant => LedgerAction::AccessGranted,
            MemoryKernelOp::AccessRevoke => LedgerAction::AccessRevoked,
            MemoryKernelOp::AccessCheck => LedgerAction::AccessChecked,
            MemoryKernelOp::GarbageCollect => LedgerAction::MaintenanceRun,
            MemoryKernelOp::IndexRebuild => LedgerAction::MaintenanceRun,
            MemoryKernelOp::IntegrityCheck => LedgerAction::IntegrityChecked,
            MemoryKernelOp::PortCreate => LedgerAction::ChannelOpened,
            MemoryKernelOp::PortBind => LedgerAction::ChannelOpened,
            MemoryKernelOp::PortSend => LedgerAction::MessageSent,
            MemoryKernelOp::PortReceive => LedgerAction::MessageReceived,
            MemoryKernelOp::PortClose => LedgerAction::ChannelClosed,
            MemoryKernelOp::PortDelegate => LedgerAction::AccessGranted,
            MemoryKernelOp::ToolDispatch => LedgerAction::ToolDispatched,
            MemoryKernelOp::SendSignal => LedgerAction::SignalSent,
            MemoryKernelOp::RegisterSignalHandler => LedgerAction::HandlerRegistered,
            MemoryKernelOp::SetTokenBudget => LedgerAction::BudgetSet,
            MemoryKernelOp::RecordTokenUsage => LedgerAction::TokensCharged,
            _ => LedgerAction::MaintenanceRun, // Fallback for any new ops
        }
    }
}

impl LedgerAction {
    /// Check if this is a memory-related action
    pub fn is_memory(&self) -> bool {
        matches!(self, 
            LedgerAction::MemoryDeposit | LedgerAction::MemoryWithdrawal |
            LedgerAction::MemoryEviction | LedgerAction::MemoryPromotion |
            LedgerAction::MemoryDemotion | LedgerAction::MemoryCleared |
            LedgerAction::MemorySealed
        )
    }

    /// Check if this is a tool-related action
    pub fn is_tool(&self) -> bool {
        matches!(self, LedgerAction::ToolDispatched | LedgerAction::BridgeInvoked)
    }

    /// Check if this is an account lifecycle action
    pub fn is_lifecycle(&self) -> bool {
        matches!(self,
            LedgerAction::AccountOpened | LedgerAction::AccountActivated |
            LedgerAction::AccountSuspended | LedgerAction::AccountResumed |
            LedgerAction::AccountClosed
        )
    }

    /// Check if this is a session-related action
    pub fn is_session(&self) -> bool {
        matches!(self,
            LedgerAction::SessionOpened | LedgerAction::SessionClosed |
            LedgerAction::SessionCompressed
        )
    }

    /// Get a short human-readable name
    pub fn short_name(&self) -> &'static str {
        match self {
            LedgerAction::AccountOpened => "open",
            LedgerAction::AccountActivated => "activate",
            LedgerAction::AccountSuspended => "suspend",
            LedgerAction::AccountResumed => "resume",
            LedgerAction::AccountClosed => "close",
            LedgerAction::MemoryDeposit => "write",
            LedgerAction::MemoryWithdrawal => "read",
            LedgerAction::MemoryEviction => "evict",
            LedgerAction::MemoryPromotion => "promote",
            LedgerAction::MemoryDemotion => "demote",
            LedgerAction::MemoryCleared => "clear",
            LedgerAction::MemorySealed => "seal",
            LedgerAction::SessionOpened => "session+",
            LedgerAction::SessionClosed => "session-",
            LedgerAction::SessionCompressed => "compress",
            LedgerAction::ContextSaved => "save",
            LedgerAction::ContextRestored => "restore",
            LedgerAction::AccessGranted => "grant",
            LedgerAction::AccessRevoked => "revoke",
            LedgerAction::AccessChecked => "check",
            LedgerAction::ToolDispatched => "tool",
            LedgerAction::SignalSent => "signal",
            LedgerAction::HandlerRegistered => "handler",
            LedgerAction::BudgetSet => "budget",
            LedgerAction::TokensCharged => "tokens",
            LedgerAction::ComputeCharged => "compute",
            LedgerAction::LlmScheduled => "llm+",
            LedgerAction::LlmDequeued => "llm-",
            LedgerAction::MessageSent => "send",
            LedgerAction::MessageReceived => "recv",
            LedgerAction::ChannelOpened => "channel+",
            LedgerAction::ChannelClosed => "channel-",
            LedgerAction::PolicyChecked => "policy",
            LedgerAction::IntegrityChecked => "integrity",
            LedgerAction::MaintenanceRun => "maint",
            LedgerAction::BridgeRegistered => "bridge+",
            LedgerAction::BridgeInvoked => "bridge",
            LedgerAction::IdentityRegistered => "identity",
            LedgerAction::CardPublished => "card",
            LedgerAction::ContextUpdated => "context",
        }
    }
}

impl std::fmt::Display for LedgerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LedgerAction::AccountOpened => "AccountOpened",
            LedgerAction::AccountActivated => "AccountActivated",
            LedgerAction::AccountSuspended => "AccountSuspended",
            LedgerAction::AccountResumed => "AccountResumed",
            LedgerAction::AccountClosed => "AccountClosed",
            LedgerAction::MemoryDeposit => "MemoryDeposit",
            LedgerAction::MemoryWithdrawal => "MemoryWithdrawal",
            LedgerAction::MemoryEviction => "MemoryEviction",
            LedgerAction::MemoryPromotion => "MemoryPromotion",
            LedgerAction::MemoryDemotion => "MemoryDemotion",
            LedgerAction::MemoryCleared => "MemoryCleared",
            LedgerAction::MemorySealed => "MemorySealed",
            LedgerAction::SessionOpened => "SessionOpened",
            LedgerAction::SessionClosed => "SessionClosed",
            LedgerAction::SessionCompressed => "SessionCompressed",
            LedgerAction::ContextSaved => "ContextSaved",
            LedgerAction::ContextRestored => "ContextRestored",
            LedgerAction::AccessGranted => "AccessGranted",
            LedgerAction::AccessRevoked => "AccessRevoked",
            LedgerAction::AccessChecked => "AccessChecked",
            LedgerAction::ToolDispatched => "ToolDispatched",
            LedgerAction::SignalSent => "SignalSent",
            LedgerAction::HandlerRegistered => "HandlerRegistered",
            LedgerAction::BudgetSet => "BudgetSet",
            LedgerAction::TokensCharged => "TokensCharged",
            LedgerAction::ComputeCharged => "ComputeCharged",
            LedgerAction::LlmScheduled => "LlmScheduled",
            LedgerAction::LlmDequeued => "LlmDequeued",
            LedgerAction::MessageSent => "MessageSent",
            LedgerAction::MessageReceived => "MessageReceived",
            LedgerAction::ChannelOpened => "ChannelOpened",
            LedgerAction::ChannelClosed => "ChannelClosed",
            LedgerAction::PolicyChecked => "PolicyChecked",
            LedgerAction::IntegrityChecked => "IntegrityChecked",
            LedgerAction::MaintenanceRun => "MaintenanceRun",
            LedgerAction::BridgeRegistered => "BridgeRegistered",
            LedgerAction::BridgeInvoked => "BridgeInvoked",
            LedgerAction::IdentityRegistered => "IdentityRegistered",
            LedgerAction::CardPublished => "CardPublished",
            LedgerAction::ContextUpdated => "ContextUpdated",
        };
        write!(f, "{}", s)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// JOURNAL ENTRY — The core transaction record
// ═══════════════════════════════════════════════════════════════════════════

/// A single entry in the ConnectorMap General Journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    // ── Identity ──────────────────────────────────────
    /// Monotonically increasing sequence number. No gaps.
    pub seq_no: u64,
    /// Unique event identifier (format: "je:{seq_no}")
    pub event_id: String,
    /// Timestamp in milliseconds since epoch (from kernel clock)
    pub timestamp_ms: i64,

    // ── The Transaction ───────────────────────────────
    /// Who performed the action (canonical account ID)
    pub actor: AccountId,
    /// What was done (kernel operation mapped to ledger action)
    pub action: LedgerAction,
    /// What it was done to (canonical account ID, optional)
    pub target: Option<AccountId>,
    /// Measured quantity (bytes, tokens, milliseconds, count)
    pub quantity: Option<f64>,
    /// Unit of the quantity
    pub unit: Option<String>,
    /// Transaction outcome
    pub outcome: Outcome,

    // ── Chain of Custody ──────────────────────────────
    /// Verification tier of this entry
    pub verification: VerificationTier,
    /// Hash of the previous journal entry (HMAC chain link)
    pub prev_hash: Option<String>,
    /// Hash of this journal entry
    pub this_hash: Option<String>,
    /// References to causally preceding entries
    pub causal_refs: Vec<String>,
    /// AAPI authorization reference (if authorized)
    pub auth_ref: Option<String>,
    /// Reference to full payload (CID, packet ID, etc.)
    pub payload_ref: Option<String>,

    // ── Posting ───────────────────────────────────────
    /// Debit-side ledger line (resource consumed / state left)
    pub debit: LedgerLine,
    /// Credit-side ledger line (resource produced / state entered)
    pub credit: LedgerLine,

    // ── Context ───────────────────────────────────────
    /// Human-readable description
    pub description: String,
    /// Memo / reason for the operation
    pub memo: Option<String>,
    /// Session this entry belongs to
    pub session: Option<String>,
    /// Duration of the operation in microseconds
    pub duration_us: Option<u64>,
}

impl JournalEntry {
    /// Create event_id from seq_no
    pub fn make_event_id(seq_no: u64) -> String {
        format!("je:{}", seq_no)
    }

    /// Quick constructor for simple journal entries.
    /// 
    /// Creates a minimal entry with sensible defaults. Perfect for testing
    /// or when you just need a basic entry without all the ceremony.
    ///
    /// ```rust
    /// use connector_engine::books::{JournalEntry, LedgerAction, Outcome};
    /// 
    /// let entry = JournalEntry::quick("agent:test", LedgerAction::ToolDispatched, Outcome::Cleared);
    /// ```
    pub fn quick(actor: &str, action: LedgerAction, outcome: Outcome) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let seq_no = now_ms as u64 % 1_000_000; // Simple seq for quick entries
        let (debit, credit) = post(&action, &outcome, None, None, None);
        
        Self {
            seq_no,
            event_id: Self::make_event_id(seq_no),
            timestamp_ms: now_ms,
            actor: AccountId::parse_or_system(actor),
            action,
            target: None,
            quantity: None,
            unit: None,
            outcome,
            verification: VerificationTier::Unverified,
            prev_hash: None,
            this_hash: None,
            causal_refs: vec![],
            auth_ref: None,
            payload_ref: None,
            debit,
            credit,
            description: String::new(),
            memo: None,
            session: None,
            duration_us: None,
        }
    }

    /// Builder-style: set the target account
    pub fn with_target(mut self, target: AccountId) -> Self {
        self.target = Some(target);
        self
    }

    /// Builder-style: set quantity and unit
    pub fn with_quantity(mut self, qty: f64, unit: &str) -> Self {
        self.quantity = Some(qty);
        self.unit = Some(unit.to_string());
        self
    }

    /// Builder-style: set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Builder-style: set session
    pub fn with_session(mut self, session: &str) -> Self {
        self.session = Some(session.to_string());
        self
    }

    /// Builder-style: set memo
    pub fn with_memo(mut self, memo: &str) -> Self {
        self.memo = Some(memo.to_string());
        self
    }

    /// Check if this entry was successful
    pub fn is_success(&self) -> bool {
        self.outcome == Outcome::Cleared
    }

    /// Check if this entry failed or was rejected
    pub fn is_failure(&self) -> bool {
        matches!(self.outcome, Outcome::Failed | Outcome::Rejected)
    }

    /// Validate invariants for this entry
    pub fn validate(&self) -> Result<(), JournalEntryError> {
        // Invariant 9: Complete posting — both debit and credit must exist
        // (They always exist by construction, but we check they're not empty codes)
        if self.debit.account_code.is_empty() {
            return Err(JournalEntryError::IncompletePosting("debit account_code is empty".into()));
        }
        if self.credit.account_code.is_empty() {
            return Err(JournalEntryError::IncompletePosting("credit account_code is empty".into()));
        }

        // Invariant 6: Canonical identity — actor must have valid format
        if self.actor.id.is_empty() {
            return Err(JournalEntryError::InvalidAccountId("actor id is empty".into()));
        }

        // Invariant 1: event_id must match seq_no
        let expected_event_id = Self::make_event_id(self.seq_no);
        if self.event_id != expected_event_id {
            return Err(JournalEntryError::EventIdMismatch {
                expected: expected_event_id,
                actual: self.event_id.clone(),
            });
        }

        Ok(())
    }
}

/// Errors that can occur when validating or processing journal entries.
#[derive(Debug, Clone, Error)]
pub enum JournalEntryError {
    /// Posting is incomplete (missing debit or credit account code)
    #[error("incomplete posting: {0}")]
    IncompletePosting(String),

    /// Account ID is invalid or malformed
    #[error("invalid account ID: {0}")]
    InvalidAccountId(String),

    /// Event ID does not match expected format for seq_no
    #[error("event ID mismatch: expected {expected}, got {actual}")]
    EventIdMismatch { expected: String, actual: String },

    /// HMAC chain is broken (prev_hash doesn't match)
    #[error("chain break: expected prev_hash {expected_prev}, got {actual_prev}")]
    ChainBreak { expected_prev: String, actual_prev: String },

    /// Timestamp is invalid or out of range
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// Verification tier mismatch
    #[error("verification tier mismatch: expected {expected}, got {actual}")]
    VerificationMismatch { expected: String, actual: String },
}

// ═══════════════════════════════════════════════════════════════════════════
// POSTING RULES — How each action maps to debit/credit lines
// ═══════════════════════════════════════════════════════════════════════════

/// Generate debit and credit lines for a given action and outcome.
/// This implements Section 5 of CONNECTORMAP.md — Ledger Posting Rules.
pub fn post(
    action: &LedgerAction,
    outcome: &Outcome,
    quantity: Option<f64>,
    unit: Option<&str>,
    reference: Option<String>,
) -> (LedgerLine, LedgerLine) {
    let qty = quantity.unwrap_or(1.0);
    let u = unit.unwrap_or("count");

    match action {
        // Resource flow events
        LedgerAction::MemoryDeposit => (
            LedgerLine::new(accounts::MEMORY_DEPOSITS, qty, u, reference.clone()),
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference),
        ),
        LedgerAction::MemoryWithdrawal => (
            LedgerLine::new(accounts::MEMORY_WITHDRAWALS, qty, u, reference.clone()),
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference),
        ),
        LedgerAction::MemorySealed => (
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference.clone()),
            LedgerLine::new(accounts::SEALED_MEMORY, qty, u, reference),
        ),
        LedgerAction::MemoryEviction => (
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference.clone()),
            LedgerLine::new(accounts::MEMORY_WITHDRAWALS, qty, u, reference),
        ),
        LedgerAction::MemoryPromotion | LedgerAction::MemoryDemotion => (
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference.clone()),
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference),
        ),
        LedgerAction::MemoryCleared => (
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference.clone()),
            LedgerLine::new(accounts::MEMORY_MAINTENANCE, qty, u, reference),
        ),

        // State transition events
        LedgerAction::AccountOpened => (
            LedgerLine::new(accounts::REGISTRATIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::RUNNING_AGENTS, 1.0, "count", reference),
        ),
        LedgerAction::AccountClosed => (
            LedgerLine::new(accounts::RUNNING_AGENTS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::TERMINATIONS, 1.0, "count", reference),
        ),
        LedgerAction::AccountSuspended => (
            LedgerLine::new(accounts::RUNNING_AGENTS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::PAUSES_SUSPENSIONS, 1.0, "count", reference),
        ),
        LedgerAction::AccountResumed | LedgerAction::AccountActivated => (
            LedgerLine::new(accounts::STARTS_RESUMES, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::RUNNING_AGENTS, 1.0, "count", reference),
        ),

        // Session events
        LedgerAction::SessionOpened => (
            LedgerLine::new(accounts::REGISTRATIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::ACTIVE_SESSIONS, 1.0, "count", reference),
        ),
        LedgerAction::SessionClosed => (
            LedgerLine::new(accounts::ACTIVE_SESSIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::TERMINATIONS, 1.0, "count", reference),
        ),
        LedgerAction::SessionCompressed => (
            LedgerLine::new(accounts::ACTIVE_SESSIONS, qty, u, reference.clone()),
            LedgerLine::new(accounts::MEMORY_MAINTENANCE, qty, u, reference),
        ),

        // Authorization events
        LedgerAction::AccessGranted => (
            LedgerLine::new(accounts::ACCESS_GRANTS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::AGENT_CAPABILITIES, 1.0, "count", reference),
        ),
        LedgerAction::AccessRevoked => (
            LedgerLine::new(accounts::AGENT_CAPABILITIES, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::ACCESS_GRANTS, 1.0, "count", reference),
        ),
        LedgerAction::AccessChecked => {
            match outcome {
                Outcome::Cleared => (
                    LedgerLine::new(accounts::POLICY_CHECKS, 1.0, "count", reference.clone()),
                    LedgerLine::new(accounts::HMAC_CHAIN, 1.0, "count", reference),
                ),
                Outcome::Rejected => (
                    LedgerLine::new(accounts::ACCESS_DENIALS, 1.0, "count", reference.clone()),
                    LedgerLine::new(accounts::PENDING_APPROVALS, 1.0, "count", reference),
                ),
                _ => (
                    LedgerLine::new(accounts::POLICY_CHECKS, 1.0, "count", reference.clone()),
                    LedgerLine::new(accounts::HMAC_CHAIN, 1.0, "count", reference),
                ),
            }
        }
        LedgerAction::PolicyChecked => (
            LedgerLine::new(accounts::POLICY_CHECKS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::HMAC_CHAIN, 1.0, "count", reference),
        ),

        // Tool events
        LedgerAction::ToolDispatched => (
            LedgerLine::new(accounts::TOOL_CALLS, qty, u, reference.clone()),
            LedgerLine::new(accounts::TOOL_EXEC_TIME, qty, u, reference),
        ),
        LedgerAction::BridgeInvoked => (
            LedgerLine::new(accounts::MCP_BRIDGE_CALLS, qty, u, reference.clone()),
            LedgerLine::new(accounts::TOOL_EXEC_TIME, qty, u, reference),
        ),
        LedgerAction::BridgeRegistered => (
            LedgerLine::new(accounts::REGISTRATIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::AGENT_CAPABILITIES, 1.0, "count", reference),
        ),

        // Cost events
        LedgerAction::TokensCharged => (
            LedgerLine::new(accounts::INPUT_TOKENS, qty, "tokens", reference.clone()),
            LedgerLine::new(accounts::DOLLAR_COST, qty, "tokens", reference),
        ),
        LedgerAction::ComputeCharged => (
            LedgerLine::new(accounts::LLM_COMPUTE_TIME, qty, "ms", reference.clone()),
            LedgerLine::new(accounts::DOLLAR_COST, qty, "ms", reference),
        ),
        LedgerAction::BudgetSet => (
            LedgerLine::new(accounts::POLICY_CHECKS, qty, "tokens", reference.clone()),
            LedgerLine::new(accounts::AGENT_CAPABILITIES, qty, "tokens", reference),
        ),
        LedgerAction::LlmScheduled | LedgerAction::LlmDequeued => (
            LedgerLine::new(accounts::LLM_COMPUTE_TIME, qty, u, reference.clone()),
            LedgerLine::new(accounts::PENDING_TOOL_RESULTS, qty, u, reference),
        ),

        // Messaging events
        LedgerAction::MessageSent => (
            LedgerLine::new(accounts::INTER_AGENT_MESSAGES, qty, u, reference.clone()),
            LedgerLine::new(accounts::PENDING_TOOL_RESULTS, qty, u, reference),
        ),
        LedgerAction::MessageReceived => (
            LedgerLine::new(accounts::PENDING_TOOL_RESULTS, qty, u, reference.clone()),
            LedgerLine::new(accounts::INTER_AGENT_MESSAGES, qty, u, reference),
        ),
        LedgerAction::ChannelOpened => (
            LedgerLine::new(accounts::REGISTRATIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::AGENT_CAPABILITIES, 1.0, "count", reference),
        ),
        LedgerAction::ChannelClosed => (
            LedgerLine::new(accounts::AGENT_CAPABILITIES, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::TERMINATIONS, 1.0, "count", reference),
        ),
        LedgerAction::SignalSent => (
            LedgerLine::new(accounts::INTER_AGENT_MESSAGES, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::HMAC_CHAIN, 1.0, "count", reference),
        ),
        LedgerAction::HandlerRegistered => (
            LedgerLine::new(accounts::REGISTRATIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::AGENT_CAPABILITIES, 1.0, "count", reference),
        ),

        // Context events
        LedgerAction::ContextSaved | LedgerAction::ContextRestored | LedgerAction::ContextUpdated => (
            LedgerLine::new(accounts::ACTIVE_MEMORY, qty, u, reference.clone()),
            LedgerLine::new(accounts::MEMORY_MAINTENANCE, qty, u, reference),
        ),

        // Integrity events
        LedgerAction::IntegrityChecked => (
            LedgerLine::new(accounts::MEMORY_MAINTENANCE, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::MERKLE_CHECKPOINTS, 1.0, "count", reference),
        ),
        LedgerAction::MaintenanceRun => (
            LedgerLine::new(accounts::MEMORY_MAINTENANCE, qty, u, reference.clone()),
            LedgerLine::new(accounts::RECONCILIATION_RESULTS, qty, u, reference),
        ),

        // Identity events
        LedgerAction::IdentityRegistered => (
            LedgerLine::new(accounts::REGISTRATIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::AGENT_CAPABILITIES, 1.0, "count", reference),
        ),
        LedgerAction::CardPublished => (
            LedgerLine::new(accounts::REGISTRATIONS, 1.0, "count", reference.clone()),
            LedgerLine::new(accounts::KNOWLEDGE_ENTITIES, 1.0, "count", reference),
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVERSION FROM KERNEL AUDIT ENTRY
// ═══════════════════════════════════════════════════════════════════════════

impl From<&KernelAuditEntry> for JournalEntry {
    fn from(entry: &KernelAuditEntry) -> Self {
        let action = LedgerAction::from_kernel_op(&entry.operation);
        let outcome = Outcome::from(&entry.outcome);

        // Resolve actor
        let actor = if entry.agent_pid.is_empty() || entry.agent_pid == "system" {
            AccountId::system("kernel")
        } else {
            AccountId::agent(&entry.agent_pid, &entry.agent_pid)
        };

        // Resolve target
        let target = entry.target.as_ref().and_then(|t| {
            if t.starts_with("ns:") {
                Some(AccountId::namespace(&t[3..]))
            } else if t.starts_with("tool:") {
                Some(AccountId::tool(&t[5..]))
            } else if t.starts_with("agent:") || t.starts_with("pid:") {
                Some(AccountId::agent(t, t))
            } else {
                None // CIDs and other refs go to payload_ref, not target
            }
        });

        // Payload ref is the target if it looks like a CID
        let payload_ref = entry.target.as_ref().and_then(|t| {
            if t.starts_with("bafy") || t.starts_with("Qm") {
                Some(t.clone())
            } else {
                None
            }
        });

        // Generate posting lines
        let (debit, credit) = post(
            &action,
            &outcome,
            None, // KernelAuditEntry doesn't have quantity in details
            None,
            payload_ref.clone(),
        );

        // Build description from natural_language if available, else construct
        let description = entry.natural_language.clone()
            .unwrap_or_else(|| format!("{}: {}", action, entry.target.as_deref().unwrap_or("-")));

        // Parse seq_no from audit_id (format: "audit:{seq_no}" or just use hash of audit_id)
        let seq_no = entry.audit_id.strip_prefix("audit:")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| {
                // Use a hash of the audit_id as fallback
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                entry.audit_id.hash(&mut hasher);
                hasher.finish()
            });

        JournalEntry {
            seq_no,
            event_id: JournalEntry::make_event_id(seq_no),
            timestamp_ms: entry.timestamp,
            actor,
            action,
            target,
            quantity: None,
            unit: None,
            outcome,
            verification: VerificationTier::Notarized,
            prev_hash: entry.before_hash.clone(),
            this_hash: entry.after_hash.clone(),
            causal_refs: entry.causal_chain.clone(),
            auth_ref: entry.vakya_id.clone(),
            payload_ref,
            debit,
            credit,
            description,
            memo: entry.reason.clone(),
            session: None, // KernelAuditEntry doesn't have session field
            duration_us: entry.duration_us,
        }
    }
}

/// Extract quantity and unit from the details JSON if present
fn extract_quantity_from_details(details: &Option<serde_json::Value>) -> (Option<f64>, Option<String>) {
    if let Some(d) = details {
        // Try common patterns
        if let Some(bytes) = d.get("bytes").and_then(|v| v.as_f64()) {
            return (Some(bytes), Some("bytes".to_string()));
        }
        if let Some(tokens) = d.get("tokens").and_then(|v| v.as_f64()) {
            return (Some(tokens), Some("tokens".to_string()));
        }
        if let Some(ms) = d.get("duration_ms").and_then(|v| v.as_f64()) {
            return (Some(ms), Some("ms".to_string()));
        }
        if let Some(count) = d.get("count").and_then(|v| v.as_f64()) {
            return (Some(count), Some("count".to_string()));
        }
    }
    (None, None)
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVERSION FROM ENGINE AUDIT ENTRY
// ═══════════════════════════════════════════════════════════════════════════

impl From<&EngineAuditEntry> for JournalEntry {
    fn from(entry: &EngineAuditEntry) -> Self {
        // Map category + action to LedgerAction
        let action = map_engine_action(&entry.category, &entry.action);
        
        // Map verdict to outcome
        let outcome = match entry.verdict.as_deref() {
            Some("allowed") | Some("success") | Some("cleared") => Outcome::Cleared,
            Some("denied") | Some("rejected") => Outcome::Rejected,
            Some("error") | Some("failed") => Outcome::Failed,
            Some("pending") => Outcome::Pending,
            Some("skipped") | Some("voided") => Outcome::Voided,
            _ => Outcome::Cleared,
        };

        // Resolve actor
        let actor = entry.agent_pid.as_ref()
            .map(|pid| AccountId::agent(pid, pid))
            .unwrap_or_else(|| AccountId::system("engine"));

        // Resolve target from resource
        let target = entry.resource.as_ref().and_then(|r| AccountId::parse(r));

        // Extract quantity from details
        let (quantity, unit) = extract_quantity_from_details(&entry.details);

        // Generate posting
        let (debit, credit) = post(&action, &outcome, quantity, unit.as_deref(), None);

        // Build description
        let description = format!("{}: {}", entry.action, entry.resource.as_deref().unwrap_or("-"));

        JournalEntry {
            seq_no: 0, // Engine entries don't have kernel seq_no; assigned during reconciliation
            event_id: format!("ee:{}", entry.timestamp),
            timestamp_ms: entry.timestamp,
            actor,
            action,
            target,
            quantity,
            unit,
            outcome,
            verification: VerificationTier::Recorded, // T1, not T0
            prev_hash: None,
            this_hash: None,
            causal_refs: vec![],
            auth_ref: None,
            payload_ref: entry.resource.clone(),
            debit,
            credit,
            description,
            memo: None,
            session: None,
            duration_us: None,
        }
    }
}

fn map_engine_action(category: &str, action: &str) -> LedgerAction {
    match (category, action) {
        ("firewall", "check") => LedgerAction::PolicyChecked,
        ("firewall", "block") => LedgerAction::AccessChecked,
        ("tool", "dispatch") => LedgerAction::ToolDispatched,
        ("tool", "result") => LedgerAction::ToolDispatched,
        ("memory", "write") => LedgerAction::MemoryDeposit,
        ("memory", "read") => LedgerAction::MemoryWithdrawal,
        ("agent", "register") => LedgerAction::AccountOpened,
        ("agent", "terminate") => LedgerAction::AccountClosed,
        ("session", "create") => LedgerAction::SessionOpened,
        ("session", "close") => LedgerAction::SessionClosed,
        ("llm", "schedule") => LedgerAction::LlmScheduled,
        ("llm", "complete") => LedgerAction::LlmDequeued,
        ("token", "charge") => LedgerAction::TokensCharged,
        ("mcp", "invoke") => LedgerAction::BridgeInvoked,
        ("mcp", "register") => LedgerAction::BridgeRegistered,
        _ => LedgerAction::MaintenanceRun,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// JOURNAL BUS — Broadcast channel for real-time journal entries
// ═══════════════════════════════════════════════════════════════════════════

use tokio::sync::broadcast;
use std::sync::Arc;

/// Journal Bus capacity (entries buffered before oldest are dropped)
pub const JOURNAL_BUS_CAPACITY: usize = 10_000;

/// The Journal Bus broadcasts journal entries to all subscribers.
/// This is a convenience layer — T0 kernel chain is the source of truth.
/// If entries are missed due to overflow, consumers re-sync from T0.
#[derive(Clone)]
pub struct JournalBus {
    sender: broadcast::Sender<Arc<JournalEntry>>,
}

impl JournalBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(JOURNAL_BUS_CAPACITY);
        Self { sender }
    }

    /// Publish a journal entry to all subscribers
    pub fn publish(&self, entry: JournalEntry) -> Result<usize, broadcast::error::SendError<Arc<JournalEntry>>> {
        self.sender.send(Arc::new(entry))
    }

    /// Subscribe to the journal bus
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<JournalEntry>> {
        self.sender.subscribe()
    }

    /// Get current number of subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.len()
    }
}

impl Default for JournalBus {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// QUERY LAYER — Filter and retrieve journal entries
// ═══════════════════════════════════════════════════════════════════════════

/// Query filter for journal entries
#[derive(Debug, Clone, Default)]
pub struct JournalQuery {
    /// Filter by actor account ID
    pub actor: Option<String>,
    /// Filter by action type
    pub action: Option<LedgerAction>,
    /// Filter by outcome
    pub outcome: Option<Outcome>,
    /// Filter by target account ID
    pub target: Option<String>,
    /// Filter by session
    pub session: Option<String>,
    /// Start time (inclusive, ms since epoch)
    pub since_ms: Option<i64>,
    /// End time (exclusive, ms since epoch)
    pub until_ms: Option<i64>,
    /// Start seq_no (inclusive)
    pub from_seq: Option<u64>,
    /// End seq_no (exclusive)
    pub to_seq: Option<u64>,
    /// Maximum entries to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

impl JournalQuery {
    /// Create a new empty query (matches everything)
    pub fn new() -> Self {
        Self::default()
    }

    /// Quick query: get last N entries
    pub fn last(n: usize) -> Self {
        Self::default().limit(n)
    }

    /// Quick query: get entries for a specific agent
    pub fn for_agent(agent_id: &str) -> Self {
        Self::default().actor(agent_id)
    }

    /// Quick query: get only successful entries
    pub fn successful() -> Self {
        Self::default().outcome(Outcome::Cleared)
    }

    /// Quick query: get only failed entries
    pub fn failures() -> Self {
        Self::default().outcome(Outcome::Failed)
    }

    /// Filter by actor account ID
    pub fn actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }

    /// Filter by action type
    pub fn action(mut self, action: LedgerAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Filter by outcome
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Filter entries after this timestamp (inclusive)
    pub fn since(mut self, since_ms: i64) -> Self {
        self.since_ms = Some(since_ms);
        self
    }

    /// Filter entries before this timestamp (exclusive)
    pub fn until(mut self, until_ms: i64) -> Self {
        self.until_ms = Some(until_ms);
        self
    }

    /// Limit number of results
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Skip first N results
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Filter by session
    pub fn session(mut self, session: &str) -> Self {
        self.session = Some(session.to_string());
        self
    }

    /// Filter by target account
    pub fn target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    /// Check if an entry matches this query
    pub fn matches(&self, entry: &JournalEntry) -> bool {
        if let Some(ref actor) = self.actor {
            if entry.actor.id != *actor {
                return false;
            }
        }
        if let Some(ref action) = self.action {
            if entry.action != *action {
                return false;
            }
        }
        if let Some(ref outcome) = self.outcome {
            if entry.outcome != *outcome {
                return false;
            }
        }
        if let Some(ref target) = self.target {
            if let Some(ref entry_target) = entry.target {
                if entry_target.id != *target {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(ref session) = self.session {
            if entry.session.as_ref() != Some(session) {
                return false;
            }
        }
        if let Some(since) = self.since_ms {
            if entry.timestamp_ms < since {
                return false;
            }
        }
        if let Some(until) = self.until_ms {
            if entry.timestamp_ms >= until {
                return false;
            }
        }
        if let Some(from_seq) = self.from_seq {
            if entry.seq_no < from_seq {
                return false;
            }
        }
        if let Some(to_seq) = self.to_seq {
            if entry.seq_no >= to_seq {
                return false;
            }
        }
        true
    }
}

/// Query result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalQueryResult {
    pub entries: Vec<JournalEntry>,
    pub total_matched: usize,
    pub offset: usize,
    pub limit: Option<usize>,
    pub query_time_us: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// LEDGER PROJECTION — Per-account view with running totals
// ═══════════════════════════════════════════════════════════════════════════

/// Running totals for an account ledger
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LedgerTotals {
    pub entry_count: usize,
    pub cleared_count: usize,
    pub rejected_count: usize,
    pub failed_count: usize,
    pub pending_count: usize,
    pub memory_deposits_bytes: f64,
    pub memory_withdrawals_bytes: f64,
    pub memory_net_bytes: f64,
    pub tool_calls: usize,
    pub tool_cleared: usize,
    pub tool_failed: usize,
    pub tool_duration_ms: f64,
    pub tokens_in: f64,
    pub tokens_out: f64,
    pub tokens_total: f64,
    pub cost_usd: f64,
    pub computed_at_ms: i64,
}

impl LedgerTotals {
    pub fn new() -> Self {
        Self {
            computed_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            ..Default::default()
        }
    }

    /// Update totals with a new entry
    pub fn add_entry(&mut self, entry: &JournalEntry) {
        self.entry_count += 1;
        match entry.outcome {
            Outcome::Cleared => self.cleared_count += 1,
            Outcome::Rejected => self.rejected_count += 1,
            Outcome::Failed => self.failed_count += 1,
            Outcome::Pending => self.pending_count += 1,
            Outcome::Voided => {}
        }

        // Track memory
        match entry.action {
            LedgerAction::MemoryDeposit => {
                if let Some(qty) = entry.quantity {
                    self.memory_deposits_bytes += qty;
                    self.memory_net_bytes += qty;
                }
            }
            LedgerAction::MemoryWithdrawal => {
                if let Some(qty) = entry.quantity {
                    self.memory_withdrawals_bytes += qty;
                    self.memory_net_bytes -= qty;
                }
            }
            _ => {}
        }

        // Track tools
        if entry.action == LedgerAction::ToolDispatched {
            self.tool_calls += 1;
            match entry.outcome {
                Outcome::Cleared => {
                    self.tool_cleared += 1;
                    if let Some(qty) = entry.quantity {
                        self.tool_duration_ms += qty;
                    }
                }
                Outcome::Failed => self.tool_failed += 1,
                _ => {}
            }
        }

        // Track tokens (from TokensCharged entries)
        if entry.action == LedgerAction::TokensCharged {
            if let Some(qty) = entry.quantity {
                self.tokens_total += qty;
                // TODO: distinguish in/out from details
            }
        }
    }
}

/// Account ledger — filtered journal view with running totals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLedger {
    pub account: AccountId,
    pub status: String,
    pub session: Option<String>,
    pub since_ms: i64,
    pub entries: Vec<JournalEntry>,
    pub totals: LedgerTotals,
    pub chain_verified: bool,
}

impl AccountLedger {
    /// Build a ledger from a list of journal entries for a specific account
    pub fn from_entries(account: AccountId, entries: Vec<JournalEntry>) -> Self {
        let mut totals = LedgerTotals::new();
        let since_ms = entries.first().map(|e| e.timestamp_ms).unwrap_or(0);
        let session = entries.first().and_then(|e| e.session.clone());

        for entry in &entries {
            totals.add_entry(entry);
        }

        let chain_verified = verify_journal_hash_chain(&entries);
        Self {
            account,
            status: "Active".to_string(), // TODO: derive from entries
            session,
            since_ms,
            entries,
            totals,
            chain_verified,
        }
    }
}

/// Honest chain check: consecutive this_hash → next prev_hash. Missing hashes ⇒ unverified.
fn verify_journal_hash_chain(entries: &[JournalEntry]) -> bool {
    if entries.is_empty() {
        return true;
    }
    // If no entry carries hashes, we cannot claim verified.
    if entries
        .iter()
        .all(|e| e.this_hash.is_none() && e.prev_hash.is_none())
    {
        return false;
    }
    let mut prev: Option<String> = None;
    for (i, entry) in entries.iter().enumerate() {
        match (&prev, &entry.prev_hash) {
            (None, _) if i == 0 => {}
            (Some(expected), Some(actual)) if expected == actual => {}
            _ => return false,
        }
        match &entry.this_hash {
            Some(h) => prev = Some(h.clone()),
            None => return false,
        }
    }
    true
}

// ═══════════════════════════════════════════════════════════════════════════
// ACCOUNT STATEMENT — Full investigation view
// ═══════════════════════════════════════════════════════════════════════════

/// Memory position in a statement
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryPosition {
    pub deposits_count: usize,
    pub deposits_bytes: f64,
    pub withdrawals_count: usize,
    pub withdrawals_bytes: f64,
    pub net_bytes: f64,
    pub packets_held: Vec<String>,
    pub shared_reads: Vec<SharedRead>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedRead {
    pub packet_cid: String,
    pub reader: String,
    pub timestamp_ms: i64,
}

/// Tool usage in a statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsage {
    pub tool_id: String,
    pub calls: usize,
    pub cleared: usize,
    pub failed: usize,
    pub duration_ms: f64,
    pub cost_usd: f64,
}

/// Token and cost position
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenPosition {
    pub input_tokens: f64,
    pub output_tokens: f64,
    pub total_tokens: f64,
    pub model: Option<String>,
    pub cost_usd: f64,
}

/// Trust position with decomposed dimensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPosition {
    pub score: u8,
    pub grade: char,
    pub integrity: u8,
    pub policy_compliance: u8,
    pub execution_success: u8,
    pub provenance: u8,
    pub reconciliation: u8,
    pub anomaly_penalty: u8,
}

impl TrustPosition {
    /// Compute trust position from ledger totals
    pub fn from_totals(totals: &LedgerTotals, chain_verified: bool) -> Self {
        let integrity = if chain_verified { 100 } else { 0 };
        let policy_compliance = if totals.rejected_count == 0 { 100 } else {
            ((totals.cleared_count as f64 / (totals.cleared_count + totals.rejected_count) as f64) * 100.0) as u8
        };
        let execution_success = if totals.entry_count == 0 { 100 } else {
            ((totals.cleared_count as f64 / totals.entry_count as f64) * 100.0) as u8
        };
        let provenance = 100; // TODO: check causal_refs completeness
        let reconciliation = 100; // TODO: check reconciliation status
        let anomaly_penalty = 100; // TODO: integrate with BehaviorAnalyzer

        // Weighted sum (Section 11 of CONNECTORMAP.md)
        let score = (
            (integrity as f64 * 0.25) +
            (policy_compliance as f64 * 0.20) +
            (execution_success as f64 * 0.20) +
            (provenance as f64 * 0.15) +
            (reconciliation as f64 * 0.10) +
            (anomaly_penalty as f64 * 0.10)
        ) as u8;

        let grade = match score {
            90..=100 => 'A',
            75..=89 => 'B',
            60..=74 => 'C',
            40..=59 => 'D',
            _ => 'F',
        };

        Self {
            score,
            grade,
            integrity,
            policy_compliance,
            execution_success,
            provenance,
            reconciliation,
            anomaly_penalty,
        }
    }
}

/// Authorization position
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizationPosition {
    pub clearance_level: u8,
    pub access_grants: Vec<String>,
    pub denials: usize,
    pub policy_checks: usize,
}

/// Chain of custody info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustody {
    pub first_seq: u64,
    pub first_hash: Option<String>,
    pub last_seq: u64,
    pub last_hash: Option<String>,
    pub chain_length: usize,
    pub integrity: String,
    pub merkle_root: Option<String>,
}

/// Full account statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatement {
    // Header
    pub account: AccountId,
    pub class: String,
    pub status: String,
    pub model: Option<String>,
    pub namespace: Option<String>,
    pub session: Option<String>,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    pub generated_at_ms: i64,

    // Transaction history
    pub transactions: Vec<JournalEntry>,

    // Position sections
    pub memory: MemoryPosition,
    pub tools: Vec<ToolUsage>,
    pub tokens: TokenPosition,
    pub trust: TrustPosition,
    pub authorization: AuthorizationPosition,
    pub chain: ChainOfCustody,

    // Metadata
    pub verification_tier: VerificationTier,
}

impl AccountStatement {
    /// Build a statement from a ledger
    pub fn from_ledger(ledger: AccountLedger) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let period_start_ms = ledger.entries.first().map(|e| e.timestamp_ms).unwrap_or(now_ms);
        let period_end_ms = ledger.entries.last().map(|e| e.timestamp_ms).unwrap_or(now_ms);

        // Build memory position
        let mut memory = MemoryPosition::default();
        for entry in &ledger.entries {
            match entry.action {
                LedgerAction::MemoryDeposit => {
                    memory.deposits_count += 1;
                    if let Some(qty) = entry.quantity {
                        memory.deposits_bytes += qty;
                        memory.net_bytes += qty;
                    }
                    if let Some(ref cid) = entry.payload_ref {
                        memory.packets_held.push(cid.clone());
                    }
                }
                LedgerAction::MemoryWithdrawal => {
                    memory.withdrawals_count += 1;
                    if let Some(qty) = entry.quantity {
                        memory.withdrawals_bytes += qty;
                        memory.net_bytes -= qty;
                    }
                }
                _ => {}
            }
        }

        // Build tool usage
        let mut tool_map: HashMap<String, ToolUsage> = HashMap::new();
        for entry in &ledger.entries {
            if entry.action == LedgerAction::ToolDispatched {
                let tool_id = entry.target.as_ref()
                    .map(|t| t.id.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                let usage = tool_map.entry(tool_id.clone()).or_insert(ToolUsage {
                    tool_id,
                    calls: 0,
                    cleared: 0,
                    failed: 0,
                    duration_ms: 0.0,
                    cost_usd: 0.0,
                });
                usage.calls += 1;
                match entry.outcome {
                    Outcome::Cleared => {
                        usage.cleared += 1;
                        if let Some(qty) = entry.quantity {
                            usage.duration_ms += qty;
                        }
                    }
                    Outcome::Failed => usage.failed += 1,
                    _ => {}
                }
            }
        }
        let tools: Vec<ToolUsage> = tool_map.into_values().collect();

        // Build token position
        let tokens = TokenPosition {
            input_tokens: 0.0, // TODO: extract from entries
            output_tokens: 0.0,
            total_tokens: ledger.totals.tokens_total,
            model: None, // TODO: extract from entries
            cost_usd: ledger.totals.cost_usd,
        };

        // Build trust position
        let trust = TrustPosition::from_totals(&ledger.totals, ledger.chain_verified);

        // Build authorization position
        let mut authorization = AuthorizationPosition::default();
        for entry in &ledger.entries {
            match entry.action {
                LedgerAction::AccessGranted => {
                    if let Some(ref target) = entry.target {
                        authorization.access_grants.push(target.id.clone());
                    }
                }
                LedgerAction::AccessChecked => {
                    authorization.policy_checks += 1;
                    if entry.outcome == Outcome::Rejected {
                        authorization.denials += 1;
                    }
                }
                _ => {}
            }
        }

        // Build chain of custody
        let chain = ChainOfCustody {
            first_seq: ledger.entries.first().map(|e| e.seq_no).unwrap_or(0),
            first_hash: ledger.entries.first().and_then(|e| e.this_hash.clone()),
            last_seq: ledger.entries.last().map(|e| e.seq_no).unwrap_or(0),
            last_hash: ledger.entries.last().and_then(|e| e.this_hash.clone()),
            chain_length: ledger.entries.len(),
            integrity: if ledger.chain_verified { "VERIFIED".to_string() } else { "UNVERIFIED".to_string() },
            merkle_root: None, // TODO: compute or fetch
        };

        Self {
            account: ledger.account.clone(),
            class: format!("{:?}", ledger.account.class),
            status: ledger.status,
            model: None,
            namespace: None,
            session: ledger.session,
            period_start_ms,
            period_end_ms,
            generated_at_ms: now_ms,
            transactions: ledger.entries,
            memory,
            tools,
            tokens,
            trust,
            authorization,
            chain,
            verification_tier: VerificationTier::Derived,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM POSITION — Overall system state report
// ═══════════════════════════════════════════════════════════════════════════

/// Resources held by the system.
///
/// Fields the kernel cannot currently measure are `Option` and serialise as
/// `null`. They must never be reported as `0`, which reads as a measurement.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourcesHeld {
    pub active_memory_count: usize,
    pub active_memory_bytes: u64,
    /// Seal state is per-agent-snapshot, not tracked in the global packet table.
    pub sealed_memory_count: Option<usize>,
    pub sealed_memory_bytes: Option<u64>,
    pub shared_memory_count: Option<usize>,
    pub shared_memory_bytes: Option<u64>,
    pub running_agents: usize,
    /// Pause and suspend both resolve to `AgentStatus::Suspended`, so a pause
    /// count cannot be separated out — it is included in `suspended_agents`.
    pub paused_agents: Option<usize>,
    pub suspended_agents: usize,
    pub active_sessions: usize,
    pub capabilities: Option<usize>,
    pub knowledge_entities: usize,
}

/// Pending obligations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingObligations {
    pub pending_approvals: usize,
    pub pending_tool_results: usize,
    pub escrow_holds: usize,
}

/// Integrity position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityPosition {
    pub trust_score: u8,
    /// Full letter grade — `String` rather than `char` so `A+` survives.
    pub trust_grade: String,
    pub chain_length: u64,
    pub chain_verified: bool,
    pub last_reconciliation_ms: Option<i64>,
    pub reconciliation_status: String,
}

/// Cost position
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CostPosition {
    pub today_tokens: u64,
    pub today_cost_usd: f64,
    pub month_tokens: u64,
    pub month_cost_usd: f64,
}

/// System position report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPosition {
    pub generated_at_ms: i64,
    pub resources: ResourcesHeld,
    pub pending: PendingObligations,
    pub integrity: IntegrityPosition,
    pub cost: CostPosition,
    pub recent_entries: Vec<JournalEntry>,
}

// ═══════════════════════════════════════════════════════════════════════════
// RECONCILIATION — T0 vs T1 verification
// ═══════════════════════════════════════════════════════════════════════════

/// Reconciliation check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationCheck {
    pub name: String,
    pub passed: bool,
    pub t0_value: String,
    pub t1_value: String,
    pub details: Option<String>,
}

/// Full reconciliation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub generated_at_ms: i64,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    pub t0_count: u64,
    pub t1_count: u64,
    pub duration_ms: u64,
    pub checks: Vec<ReconciliationCheck>,
    pub hmac_chain_verified: bool,
    pub hmac_breaks: usize,
    pub merkle_checkpoints_verified: usize,
    pub outcome_mismatches: usize,
    pub orphan_entries: usize,
    pub verdict: String,
    pub scitt_receipt_cid: Option<String>,
}

impl ReconciliationReport {
    /// Create a new reconciliation report
    pub fn new(t0_entries: &[JournalEntry], t1_entries: &[JournalEntry]) -> Self {
        let start = std::time::Instant::now();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let period_start_ms = t0_entries.first().map(|e| e.timestamp_ms).unwrap_or(now_ms);
        let period_end_ms = t0_entries.last().map(|e| e.timestamp_ms).unwrap_or(now_ms);

        let mut checks = Vec::new();

        // Check 1: Entry count
        let count_match = t0_entries.len() == t1_entries.len();
        checks.push(ReconciliationCheck {
            name: "Entry count".to_string(),
            passed: count_match,
            t0_value: t0_entries.len().to_string(),
            t1_value: t1_entries.len().to_string(),
            details: None,
        });

        // Check 2: HMAC chain walk
        let mut hmac_breaks = 0;
        let mut prev_hash: Option<String> = None;
        for entry in t0_entries {
            if entry.verification == VerificationTier::Notarized {
                if let Some(ref expected) = prev_hash {
                    if entry.prev_hash.as_ref() != Some(expected) {
                        hmac_breaks += 1;
                    }
                }
                prev_hash = entry.this_hash.clone();
            }
        }
        checks.push(ReconciliationCheck {
            name: "HMAC chain walk".to_string(),
            passed: hmac_breaks == 0,
            t0_value: format!("{} links", t0_entries.len()),
            t1_value: "—".to_string(),
            details: if hmac_breaks > 0 { Some(format!("{} breaks", hmac_breaks)) } else { None },
        });

        // Check 3: Outcome agreement
        let mut outcome_mismatches = 0;
        for (t0, t1) in t0_entries.iter().zip(t1_entries.iter()) {
            if t0.outcome != t1.outcome {
                outcome_mismatches += 1;
            }
        }
        checks.push(ReconciliationCheck {
            name: "Outcome agreement".to_string(),
            passed: outcome_mismatches == 0,
            t0_value: format!("{}/{}", t0_entries.len() - outcome_mismatches, t0_entries.len()),
            t1_value: format!("{}/{}", t1_entries.len() - outcome_mismatches, t1_entries.len()),
            details: if outcome_mismatches > 0 { Some(format!("{} mismatches", outcome_mismatches)) } else { None },
        });

        let all_passed = checks.iter().all(|c| c.passed);
        let verdict = if all_passed { "RECONCILED" } else { "DIVERGED" };

        Self {
            generated_at_ms: now_ms,
            period_start_ms,
            period_end_ms,
            t0_count: t0_entries.len() as u64,
            t1_count: t1_entries.len() as u64,
            duration_ms: start.elapsed().as_millis() as u64,
            checks,
            hmac_chain_verified: hmac_breaks == 0,
            hmac_breaks,
            merkle_checkpoints_verified: 0, // TODO: implement
            outcome_mismatches,
            orphan_entries: 0, // TODO: implement
            verdict: verdict.to_string(),
            scitt_receipt_cid: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id_parsing() {
        let agent = AccountId::parse("agent:pid:000003").unwrap();
        assert_eq!(agent.class, AccountClass::Agent);
        assert_eq!(agent.id, "agent:pid:000003");

        let ns = AccountId::parse("ns:research").unwrap();
        assert_eq!(ns.class, AccountClass::Namespace);

        let tool = AccountId::parse("tool:web_search").unwrap();
        assert_eq!(tool.class, AccountClass::Tool);
    }

    #[test]
    fn test_account_id_constructors() {
        let agent = AccountId::agent("pid:000003", "research_agent");
        assert_eq!(agent.id, "agent:pid:000003");
        assert_eq!(agent.display_name, "research_agent");

        let ns = AccountId::namespace("research");
        assert_eq!(ns.id, "ns:research");
    }

    #[test]
    fn test_posting_rules_memory_deposit() {
        let (debit, credit) = post(
            &LedgerAction::MemoryDeposit,
            &Outcome::Cleared,
            Some(1400.0),
            Some("bytes"),
            Some("bafy..72a3".to_string()),
        );

        assert_eq!(debit.account_code, accounts::MEMORY_DEPOSITS);
        assert_eq!(credit.account_code, accounts::ACTIVE_MEMORY);
        assert_eq!(debit.amount, 1400.0);
        assert_eq!(debit.unit, "bytes");
    }

    #[test]
    fn test_posting_rules_access_denied() {
        let (debit, credit) = post(
            &LedgerAction::AccessChecked,
            &Outcome::Rejected,
            None,
            None,
            Some("ns:confidential".to_string()),
        );

        assert_eq!(debit.account_code, accounts::ACCESS_DENIALS);
        assert_eq!(credit.account_code, accounts::PENDING_APPROVALS);
    }

    #[test]
    fn test_posting_rules_tool_dispatch() {
        let (debit, credit) = post(
            &LedgerAction::ToolDispatched,
            &Outcome::Cleared,
            Some(420.0),
            Some("ms"),
            Some("tool:web_search".to_string()),
        );

        assert_eq!(debit.account_code, accounts::TOOL_CALLS);
        assert_eq!(credit.account_code, accounts::TOOL_EXEC_TIME);
        assert_eq!(debit.amount, 420.0);
    }

    #[test]
    fn test_journal_entry_validation() {
        let entry = JournalEntry {
            seq_no: 1247,
            event_id: "je:1247".to_string(),
            timestamp_ms: 1710612678103,
            actor: AccountId::agent("pid:000003", "research_agent"),
            action: LedgerAction::ToolDispatched,
            target: Some(AccountId::tool("web_search")),
            quantity: Some(420.0),
            unit: Some("ms".to_string()),
            outcome: Outcome::Cleared,
            verification: VerificationTier::Notarized,
            prev_hash: Some("a8f3..21cd".to_string()),
            this_hash: Some("7b2e..9a01".to_string()),
            causal_refs: vec!["je:1245".to_string(), "je:1246".to_string()],
            auth_ref: Some("vakya:v0012".to_string()),
            payload_ref: Some("bafy..72a3".to_string()),
            debit: LedgerLine::new(accounts::TOOL_CALLS, 420.0, "ms", None),
            credit: LedgerLine::new(accounts::TOOL_EXEC_TIME, 420.0, "ms", None),
            description: "ToolDispatched: tool:web_search".to_string(),
            memo: None,
            session: Some("session:sess:001".to_string()),
            duration_us: Some(420000),
        };

        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_journal_entry_validation_fails_on_mismatched_event_id() {
        let entry = JournalEntry {
            seq_no: 1247,
            event_id: "je:9999".to_string(), // Wrong!
            timestamp_ms: 1710612678103,
            actor: AccountId::agent("pid:000003", "research_agent"),
            action: LedgerAction::ToolDispatched,
            target: None,
            quantity: None,
            unit: None,
            outcome: Outcome::Cleared,
            verification: VerificationTier::Notarized,
            prev_hash: None,
            this_hash: None,
            causal_refs: vec![],
            auth_ref: None,
            payload_ref: None,
            debit: LedgerLine::new(accounts::TOOL_CALLS, 1.0, "count", None),
            credit: LedgerLine::new(accounts::TOOL_EXEC_TIME, 1.0, "count", None),
            description: "test".to_string(),
            memo: None,
            session: None,
            duration_us: None,
        };

        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_ledger_action_from_kernel_op() {
        assert_eq!(
            LedgerAction::from_kernel_op(&MemoryKernelOp::AgentRegister),
            LedgerAction::AccountOpened
        );
        assert_eq!(
            LedgerAction::from_kernel_op(&MemoryKernelOp::MemWrite),
            LedgerAction::MemoryDeposit
        );
        assert_eq!(
            LedgerAction::from_kernel_op(&MemoryKernelOp::ToolDispatch),
            LedgerAction::ToolDispatched
        );
    }

    #[test]
    fn test_outcome_from_op_outcome() {
        assert_eq!(Outcome::from(&OpOutcome::Success), Outcome::Cleared);
        assert_eq!(Outcome::from(&OpOutcome::Denied), Outcome::Rejected);
        assert_eq!(Outcome::from(&OpOutcome::Failed), Outcome::Failed);
        assert_eq!(Outcome::from(&OpOutcome::Skipped), Outcome::Voided);
        assert_eq!(Outcome::from(&OpOutcome::Pending), Outcome::Pending);
    }

    #[test]
    fn test_account_labels() {
        assert_eq!(accounts::label(accounts::ACTIVE_MEMORY), "Active Memory");
        assert_eq!(accounts::label(accounts::TOOL_CALLS), "Tool Calls");
        assert_eq!(accounts::label(accounts::ACCESS_DENIALS), "Access Denials");
        assert_eq!(accounts::label("9999"), "Unknown Account");
    }

    #[test]
    fn test_verification_tier_methods() {
        assert_eq!(VerificationTier::Notarized.tier_number(), 0);
        assert_eq!(VerificationTier::Recorded.tier_number(), 1);
        assert_eq!(VerificationTier::Derived.tier_number(), 2);
        assert_eq!(VerificationTier::Unverified.tier_number(), 3);

        assert!(VerificationTier::Notarized.is_authoritative());
        assert!(!VerificationTier::Recorded.is_authoritative());
        assert!(!VerificationTier::Derived.is_authoritative());
        assert!(!VerificationTier::Unverified.is_authoritative());

        assert_eq!(VerificationTier::Notarized.name(), "T0 Notarized");
        assert_eq!(VerificationTier::Derived.name(), "T2 Derived");
    }

    #[test]
    fn test_ledger_line_creation() {
        let line = LedgerLine::new(accounts::ACTIVE_MEMORY, 1024.0, "bytes", Some("bafy123".to_string()));
        assert_eq!(line.account_code, accounts::ACTIVE_MEMORY);
        assert_eq!(line.account_label, "Active Memory");
        assert_eq!(line.amount, 1024.0);
        assert_eq!(line.unit, "bytes");
        assert_eq!(line.reference, Some("bafy123".to_string()));

        let zero = LedgerLine::zero(accounts::TOOL_CALLS);
        assert_eq!(zero.amount, 0.0);
        assert_eq!(zero.unit, "count");
    }

    #[test]
    fn test_journal_query_builder() {
        let query = JournalQuery::new()
            .actor("agent:pid:000003")
            .action(LedgerAction::ToolDispatched)
            .outcome(Outcome::Cleared)
            .since(1000)
            .until(2000)
            .limit(50);

        assert_eq!(query.actor, Some("agent:pid:000003".to_string()));
        assert_eq!(query.action, Some(LedgerAction::ToolDispatched));
        assert_eq!(query.outcome, Some(Outcome::Cleared));
        assert_eq!(query.since_ms, Some(1000));
        assert_eq!(query.until_ms, Some(2000));
        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn test_journal_query_matches() {
        let entry = JournalEntry {
            seq_no: 100,
            event_id: "je:100".to_string(),
            timestamp_ms: 1500,
            actor: AccountId::agent("pid:000003", "test"),
            action: LedgerAction::ToolDispatched,
            target: None,
            quantity: None,
            unit: None,
            outcome: Outcome::Cleared,
            verification: VerificationTier::Notarized,
            prev_hash: None,
            this_hash: None,
            causal_refs: vec![],
            auth_ref: None,
            payload_ref: None,
            debit: LedgerLine::zero(accounts::TOOL_CALLS),
            credit: LedgerLine::zero(accounts::TOOL_EXEC_TIME),
            description: "test".to_string(),
            memo: None,
            session: None,
            duration_us: None,
        };

        // Should match
        let query = JournalQuery::new()
            .actor("agent:pid:000003")
            .outcome(Outcome::Cleared)
            .since(1000)
            .until(2000);
        assert!(query.matches(&entry));

        // Should not match (wrong actor)
        let query2 = JournalQuery::new().actor("agent:pid:999");
        assert!(!query2.matches(&entry));

        // Should not match (out of time range)
        let query3 = JournalQuery::new().since(2000);
        assert!(!query3.matches(&entry));
    }

    #[test]
    fn test_ledger_totals() {
        let mut totals = LedgerTotals::new();
        
        let entry1 = JournalEntry {
            seq_no: 1,
            event_id: "je:1".to_string(),
            timestamp_ms: 1000,
            actor: AccountId::agent("test", "test"),
            action: LedgerAction::MemoryDeposit,
            target: None,
            quantity: Some(1024.0),
            unit: Some("bytes".to_string()),
            outcome: Outcome::Cleared,
            verification: VerificationTier::Notarized,
            prev_hash: None,
            this_hash: None,
            causal_refs: vec![],
            auth_ref: None,
            payload_ref: None,
            debit: LedgerLine::zero(accounts::MEMORY_DEPOSITS),
            credit: LedgerLine::zero(accounts::ACTIVE_MEMORY),
            description: "test".to_string(),
            memo: None,
            session: None,
            duration_us: None,
        };

        totals.add_entry(&entry1);
        assert_eq!(totals.entry_count, 1);
        assert_eq!(totals.cleared_count, 1);
        assert_eq!(totals.memory_deposits_bytes, 1024.0);
        assert_eq!(totals.memory_net_bytes, 1024.0);
    }

    #[test]
    fn test_trust_position_calculation() {
        let mut totals = LedgerTotals::new();
        totals.entry_count = 100;
        totals.cleared_count = 95;
        totals.rejected_count = 3;
        totals.failed_count = 2;

        let trust = TrustPosition::from_totals(&totals, true);
        assert_eq!(trust.integrity, 100); // chain verified
        assert!(trust.score >= 80); // should be high with good stats
        assert!(trust.grade == 'A' || trust.grade == 'B');
    }

    #[test]
    fn test_journal_entry_quick_constructor() {
        let entry = JournalEntry::quick("agent:test", LedgerAction::ToolDispatched, Outcome::Cleared);
        assert_eq!(entry.actor.id, "agent:test");
        assert_eq!(entry.action, LedgerAction::ToolDispatched);
        assert_eq!(entry.outcome, Outcome::Cleared);
        assert!(entry.is_success());
        assert!(!entry.is_failure());
    }

    #[test]
    fn test_journal_entry_builder_pattern() {
        let entry = JournalEntry::quick("agent:test", LedgerAction::MemoryDeposit, Outcome::Cleared)
            .with_target(AccountId::namespace("research"))
            .with_quantity(1024.0, "bytes")
            .with_description("Store research data")
            .with_session("sess:001")
            .with_memo("Important findings");

        assert_eq!(entry.target.unwrap().id, "ns:research");
        assert_eq!(entry.quantity, Some(1024.0));
        assert_eq!(entry.unit, Some("bytes".to_string()));
        assert_eq!(entry.description, "Store research data");
        assert_eq!(entry.session, Some("sess:001".to_string()));
        assert_eq!(entry.memo, Some("Important findings".to_string()));
    }

    #[test]
    fn test_outcome_helpers() {
        assert!(Outcome::Cleared.is_ok());
        assert!(!Outcome::Cleared.is_err());
        assert!(!Outcome::Failed.is_ok());
        assert!(Outcome::Failed.is_err());
        assert!(Outcome::Rejected.is_err());
        
        assert_eq!(Outcome::Cleared.as_str(), "cleared");
        assert_eq!(Outcome::Failed.as_str(), "failed");
        assert!(!Outcome::Cleared.emoji().is_empty());
    }

    #[test]
    fn test_ledger_action_helpers() {
        assert!(LedgerAction::MemoryDeposit.is_memory());
        assert!(LedgerAction::MemoryWithdrawal.is_memory());
        assert!(!LedgerAction::ToolDispatched.is_memory());

        assert!(LedgerAction::ToolDispatched.is_tool());
        assert!(LedgerAction::BridgeInvoked.is_tool());
        assert!(!LedgerAction::MemoryDeposit.is_tool());

        assert!(LedgerAction::AccountOpened.is_lifecycle());
        assert!(LedgerAction::AccountClosed.is_lifecycle());

        assert!(LedgerAction::SessionOpened.is_session());
        assert!(LedgerAction::SessionClosed.is_session());

        assert_eq!(LedgerAction::ToolDispatched.short_name(), "tool");
        assert_eq!(LedgerAction::MemoryDeposit.short_name(), "write");
    }

    #[test]
    fn test_account_id_helpers() {
        let agent = AccountId::agent("test", "Test Agent");
        assert!(agent.is_agent());
        assert!(!agent.is_system());

        let system = AccountId::system("kernel");
        assert!(system.is_system());
        assert!(!system.is_agent());

        // parse_or_system never fails
        let parsed = AccountId::parse_or_system("invalid");
        assert!(parsed.is_system());
        assert_eq!(parsed.display_name, "unknown");
    }

    #[test]
    fn test_journal_query_quick_constructors() {
        let last = JournalQuery::last(5);
        assert_eq!(last.limit, Some(5));

        let agent = JournalQuery::for_agent("agent:test");
        assert_eq!(agent.actor, Some("agent:test".to_string()));

        let success = JournalQuery::successful();
        assert_eq!(success.outcome, Some(Outcome::Cleared));

        let fails = JournalQuery::failures();
        assert_eq!(fails.outcome, Some(Outcome::Failed));
    }
}
