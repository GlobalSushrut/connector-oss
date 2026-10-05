//! ConnectorCTL Grammar — Verbs, Nouns, and Command Structure
//!
//! Canonical command grammar:
//! ```text
//! connectorctl <verb> <noun> [target] [time-selector] [options]
//! ```

use serde::{Deserialize, Serialize};
use super::time::TimeSelector;
use super::identity::ResourceIdentity;
use super::output::OutputMode;
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Verbs — Actions (STABLE, NEVER EXPLODE IN NUMBER)
// ═══════════════════════════════════════════════════════════════

/// Core verbs for ConnectorCTL commands.
/// These should NEVER explode in number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    // ── Lifecycle ────────────────────────────────────────────
    /// Start an agent/service
    Start,
    /// Stop an agent/service
    Stop,
    /// Pause execution
    Pause,
    /// Resume execution
    Resume,
    /// Restart agent/service
    Restart,
    /// Show current status
    Status,

    // ── Discovery ────────────────────────────────────────────
    /// List resources
    List,
    /// Show resource details
    Show,
    /// Search resources
    Find,

    // ── Inspection (TIME-AWARE) ──────────────────────────────
    /// Deep inspection
    Inspect,
    /// Review audit/compliance
    Review,
    /// Trace execution (TIME-TRAVEL)
    Trace,
    /// Live monitoring
    Watch,

    // ── Execution ────────────────────────────────────────────
    /// Execute contract/workflow
    Run,
    /// Invoke tool/action
    Invoke,
    /// Dispatch task
    Dispatch,

    // ── Governance ───────────────────────────────────────────
    /// Apply contract/policy
    Apply,
    /// Bind policy to agent
    Bind,
    /// Approve action
    Approve,
    /// Deny action
    Deny,
    /// Enforce budget/policy
    Enforce,

    // ── Trust / Proof ────────────────────────────────────────
    /// Generate proof
    Prove,
    /// Verify receipt/proof
    Verify,
    /// Seal evidence
    Seal,

    // ── System Control ───────────────────────────────────────
    /// Set context (protocol, namespace)
    Use,
    /// Attach tool to agent
    Attach,
    /// Detach tool from agent
    Detach,
    /// Set configuration
    Set,

    // ── Utilities ────────────────────────────────────────────
    /// Export audit/evidence
    Export,
    /// Explain decision
    Explain,
    /// System diagnostics
    Doctor,
}

impl Verb {
    /// Get the verb name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Restart => "restart",
            Self::Status => "status",
            Self::List => "list",
            Self::Show => "show",
            Self::Find => "find",
            Self::Inspect => "inspect",
            Self::Review => "review",
            Self::Trace => "trace",
            Self::Watch => "watch",
            Self::Run => "run",
            Self::Invoke => "invoke",
            Self::Dispatch => "dispatch",
            Self::Apply => "apply",
            Self::Bind => "bind",
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Enforce => "enforce",
            Self::Prove => "prove",
            Self::Verify => "verify",
            Self::Seal => "seal",
            Self::Use => "use",
            Self::Attach => "attach",
            Self::Detach => "detach",
            Self::Set => "set",
            Self::Export => "export",
            Self::Explain => "explain",
            Self::Doctor => "doctor",
        }
    }

    /// Check if this verb supports time selectors
    pub fn supports_time(&self) -> bool {
        matches!(
            self,
            Self::Inspect | Self::Review | Self::Trace | Self::Prove |
            Self::Verify | Self::Export | Self::Explain
        )
    }

    /// Check if this verb is read-only (no side effects)
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::Status | Self::List | Self::Show | Self::Find |
            Self::Inspect | Self::Review | Self::Trace | Self::Watch |
            Self::Verify | Self::Explain | Self::Doctor
        )
    }

    /// Get the verb category
    pub fn category(&self) -> VerbCategory {
        match self {
            Self::Start | Self::Stop | Self::Pause | Self::Resume |
            Self::Restart | Self::Status => VerbCategory::Lifecycle,

            Self::List | Self::Show | Self::Find => VerbCategory::Discovery,

            Self::Inspect | Self::Review | Self::Trace | Self::Watch => VerbCategory::Inspection,

            Self::Run | Self::Invoke | Self::Dispatch => VerbCategory::Execution,

            Self::Apply | Self::Bind | Self::Approve | Self::Deny |
            Self::Enforce => VerbCategory::Governance,

            Self::Prove | Self::Verify | Self::Seal => VerbCategory::Trust,

            Self::Use | Self::Attach | Self::Detach | Self::Set => VerbCategory::SystemControl,

            Self::Export | Self::Explain | Self::Doctor => VerbCategory::Utilities,
        }
    }

    /// Parse a verb from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "pause" => Some(Self::Pause),
            "resume" => Some(Self::Resume),
            "restart" => Some(Self::Restart),
            "status" => Some(Self::Status),
            "list" | "ls" => Some(Self::List),
            "show" => Some(Self::Show),
            "find" | "search" => Some(Self::Find),
            "inspect" => Some(Self::Inspect),
            "review" => Some(Self::Review),
            "trace" => Some(Self::Trace),
            "watch" => Some(Self::Watch),
            "run" => Some(Self::Run),
            "invoke" | "call" => Some(Self::Invoke),
            "dispatch" => Some(Self::Dispatch),
            "apply" => Some(Self::Apply),
            "bind" => Some(Self::Bind),
            "approve" => Some(Self::Approve),
            "deny" | "reject" => Some(Self::Deny),
            "enforce" => Some(Self::Enforce),
            "prove" => Some(Self::Prove),
            "verify" => Some(Self::Verify),
            "seal" => Some(Self::Seal),
            "use" => Some(Self::Use),
            "attach" => Some(Self::Attach),
            "detach" => Some(Self::Detach),
            "set" => Some(Self::Set),
            "export" => Some(Self::Export),
            "explain" => Some(Self::Explain),
            "doctor" => Some(Self::Doctor),
            _ => None,
        }
    }
}

/// Verb categories for grouping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerbCategory {
    Lifecycle,
    Discovery,
    Inspection,
    Execution,
    Governance,
    Trust,
    SystemControl,
    Utilities,
}

// ═══════════════════════════════════════════════════════════════
// Nouns — Entities (System Model)
// ═══════════════════════════════════════════════════════════════

/// Core nouns for ConnectorCTL commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Noun {
    // ── Runtime ──────────────────────────────────────────────
    /// AI agent
    Agent,
    /// Contract execution
    Run,
    /// Agent session
    Session,
    /// Background task
    Task,
    /// Multi-step workflow
    Workflow,
    /// External tool
    Tool,
    /// CLS contract
    Contract,

    // ── State + Evidence ─────────────────────────────────────
    /// Agent memory
    Memory,
    /// Audit trail
    Audit,
    /// Cryptographic proof
    Proof,
    /// Execution receipt
    Receipt,
    /// Execution trace
    Trace,
    /// System event
    Event,

    // ── Governance ───────────────────────────────────────────
    /// Governance policy
    Policy,
    /// Compliance status
    Compliance,
    /// Approval request
    Approval,
    /// Resource budget
    Budget,
    /// Investigation record
    Investigation,

    // ── Infrastructure ───────────────────────────────────────
    /// Cluster node
    Node,
    /// System service
    Service,
    /// Container
    Container,
    /// Namespace
    Namespace,
    /// Protocol (CNP, MCP, A2A)
    Protocol,
}

impl Noun {
    /// Get the noun name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Run => "run",
            Self::Session => "session",
            Self::Task => "task",
            Self::Workflow => "workflow",
            Self::Tool => "tool",
            Self::Contract => "contract",
            Self::Memory => "memory",
            Self::Audit => "audit",
            Self::Proof => "proof",
            Self::Receipt => "receipt",
            Self::Trace => "trace",
            Self::Event => "event",
            Self::Policy => "policy",
            Self::Compliance => "compliance",
            Self::Approval => "approval",
            Self::Budget => "budget",
            Self::Investigation => "investigation",
            Self::Node => "node",
            Self::Service => "service",
            Self::Container => "container",
            Self::Namespace => "namespace",
            Self::Protocol => "protocol",
        }
    }

    /// Get the plural form
    pub fn plural(&self) -> &'static str {
        match self {
            Self::Agent => "agents",
            Self::Run => "runs",
            Self::Session => "sessions",
            Self::Task => "tasks",
            Self::Workflow => "workflows",
            Self::Tool => "tools",
            Self::Contract => "contracts",
            Self::Memory => "memory",
            Self::Audit => "audits",
            Self::Proof => "proofs",
            Self::Receipt => "receipts",
            Self::Trace => "traces",
            Self::Event => "events",
            Self::Policy => "policies",
            Self::Compliance => "compliance",
            Self::Approval => "approvals",
            Self::Budget => "budgets",
            Self::Investigation => "investigations",
            Self::Node => "nodes",
            Self::Service => "services",
            Self::Container => "containers",
            Self::Namespace => "namespaces",
            Self::Protocol => "protocols",
        }
    }

    /// Get the noun category
    pub fn category(&self) -> NounCategory {
        match self {
            Self::Agent | Self::Run | Self::Session | Self::Task |
            Self::Workflow | Self::Tool | Self::Contract => NounCategory::Runtime,

            Self::Memory | Self::Audit | Self::Proof | Self::Receipt |
            Self::Trace | Self::Event => NounCategory::StateEvidence,

            Self::Policy | Self::Compliance | Self::Approval |
            Self::Budget | Self::Investigation => NounCategory::Governance,

            Self::Node | Self::Service | Self::Container |
            Self::Namespace | Self::Protocol => NounCategory::Infrastructure,
        }
    }

    /// Parse a noun from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "agent" | "agents" => Some(Self::Agent),
            "run" | "runs" => Some(Self::Run),
            "session" | "sessions" => Some(Self::Session),
            "task" | "tasks" => Some(Self::Task),
            "workflow" | "workflows" => Some(Self::Workflow),
            "tool" | "tools" => Some(Self::Tool),
            "contract" | "contracts" => Some(Self::Contract),
            "memory" => Some(Self::Memory),
            "audit" | "audits" => Some(Self::Audit),
            "proof" | "proofs" => Some(Self::Proof),
            "receipt" | "receipts" => Some(Self::Receipt),
            "trace" | "traces" => Some(Self::Trace),
            "event" | "events" => Some(Self::Event),
            "policy" | "policies" => Some(Self::Policy),
            "compliance" => Some(Self::Compliance),
            "approval" | "approvals" => Some(Self::Approval),
            "budget" | "budgets" => Some(Self::Budget),
            "investigation" | "investigations" => Some(Self::Investigation),
            "node" | "nodes" => Some(Self::Node),
            "service" | "services" => Some(Self::Service),
            "container" | "containers" => Some(Self::Container),
            "namespace" | "namespaces" => Some(Self::Namespace),
            "protocol" | "protocols" => Some(Self::Protocol),
            _ => None,
        }
    }
}

/// Noun categories for grouping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NounCategory {
    Runtime,
    StateEvidence,
    Governance,
    Infrastructure,
}

// ═══════════════════════════════════════════════════════════════
// Command — A complete ConnectorCTL command
// ═══════════════════════════════════════════════════════════════

/// A complete ConnectorCTL command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    /// The action to perform
    pub verb: Verb,

    /// The entity type to act on
    pub noun: Noun,

    /// The specific target (optional)
    pub target: Option<ResourceIdentity>,

    /// Time selector (optional, for time-travel inspection)
    pub time: TimeSelector,

    /// Output mode
    pub output: OutputMode,

    /// Additional options
    pub options: HashMap<String, String>,
}

impl Command {
    /// Create a new command
    pub fn new(verb: Verb, noun: Noun) -> Self {
        Self {
            verb,
            noun,
            target: None,
            time: TimeSelector::Now,
            output: OutputMode::default(),
            options: HashMap::new(),
        }
    }

    /// Set the target
    pub fn with_target(mut self, target: ResourceIdentity) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the time selector
    pub fn with_time(mut self, time: TimeSelector) -> Self {
        self.time = time;
        self
    }

    /// Set the output mode
    pub fn with_output(mut self, output: OutputMode) -> Self {
        self.output = output;
        self
    }

    /// Add an option
    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    /// Check if this command uses time-travel
    pub fn is_time_travel(&self) -> bool {
        self.time.is_time_travel()
    }

    /// Check if this command is read-only
    pub fn is_read_only(&self) -> bool {
        self.verb.is_read_only()
    }

    /// Format as CLI string
    pub fn to_cli_string(&self) -> String {
        let mut parts = vec![
            "connectorctl".to_string(),
            self.verb.as_str().to_string(),
            self.noun.as_str().to_string(),
        ];

        if let Some(target) = &self.target {
            parts.push(target.to_string());
        }

        // Add time selector if not "now"
        if !self.time.is_now() {
            match &self.time {
                TimeSelector::At(point) => {
                    parts.push(format!("--at {:?}", point));
                }
                TimeSelector::Last(duration) => {
                    parts.push(format!("--last {}", duration));
                }
                TimeSelector::Range(range) => {
                    parts.push(format!("--range {:?}..{:?}", range.start, range.end));
                }
                TimeSelector::Before(event_ref) => {
                    parts.push(format!("--before {}", event_ref.event_id));
                }
                TimeSelector::After(event_ref) => {
                    parts.push(format!("--after {}", event_ref.event_id));
                }
                TimeSelector::Snapshot(id) => {
                    parts.push(format!("--snapshot {}", id));
                }
                _ => {}
            }
        }

        // Add output mode if not default
        if self.output != OutputMode::default() {
            parts.push(format!("--{}", self.output.as_str()));
        }

        parts.join(" ")
    }
}

// ═══════════════════════════════════════════════════════════════
// Command Builder — Fluent API for building commands
// ═══════════════════════════════════════════════════════════════

/// Fluent builder for ConnectorCTL commands.
pub struct CommandBuilder {
    verb: Option<Verb>,
    noun: Option<Noun>,
    target: Option<ResourceIdentity>,
    time: TimeSelector,
    output: OutputMode,
    options: HashMap<String, String>,
}

impl CommandBuilder {
    pub fn new() -> Self {
        Self {
            verb: None,
            noun: None,
            target: None,
            time: TimeSelector::Now,
            output: OutputMode::default(),
            options: HashMap::new(),
        }
    }

    pub fn verb(mut self, verb: Verb) -> Self {
        self.verb = Some(verb);
        self
    }

    pub fn noun(mut self, noun: Noun) -> Self {
        self.noun = Some(noun);
        self
    }

    pub fn target(mut self, target: ResourceIdentity) -> Self {
        self.target = Some(target);
        self
    }

    pub fn time(mut self, time: TimeSelector) -> Self {
        self.time = time;
        self
    }

    pub fn output(mut self, output: OutputMode) -> Self {
        self.output = output;
        self
    }

    pub fn option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<Command, String> {
        let verb = self.verb.ok_or("Verb is required")?;
        let noun = self.noun.ok_or("Noun is required")?;

        Ok(Command {
            verb,
            noun,
            target: self.target,
            time: self.time,
            output: self.output,
            options: self.options,
        })
    }
}

impl Default for CommandBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::time::Duration;

    #[test]
    fn test_verb_parse() {
        assert_eq!(Verb::parse("start"), Some(Verb::Start));
        assert_eq!(Verb::parse("INSPECT"), Some(Verb::Inspect));
        assert_eq!(Verb::parse("ls"), Some(Verb::List));
        assert_eq!(Verb::parse("unknown"), None);
    }

    #[test]
    fn test_noun_parse() {
        assert_eq!(Noun::parse("agent"), Some(Noun::Agent));
        assert_eq!(Noun::parse("AGENTS"), Some(Noun::Agent));
        assert_eq!(Noun::parse("memory"), Some(Noun::Memory));
        assert_eq!(Noun::parse("unknown"), None);
    }

    #[test]
    fn test_verb_supports_time() {
        assert!(Verb::Inspect.supports_time());
        assert!(Verb::Trace.supports_time());
        assert!(!Verb::Start.supports_time());
        assert!(!Verb::Stop.supports_time());
    }

    #[test]
    fn test_command_builder() {
        let cmd = CommandBuilder::new()
            .verb(Verb::Inspect)
            .noun(Noun::Memory)
            .time(TimeSelector::last(Duration::minutes(10)))
            .build()
            .unwrap();

        assert_eq!(cmd.verb, Verb::Inspect);
        assert_eq!(cmd.noun, Noun::Memory);
        assert!(cmd.is_time_travel());
        assert!(cmd.is_read_only());
    }

    #[test]
    fn test_command_to_cli_string() {
        let cmd = Command::new(Verb::List, Noun::Agent);
        assert_eq!(cmd.to_cli_string(), "connectorctl list agent");
    }
}
