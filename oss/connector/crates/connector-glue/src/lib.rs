//! # GLUE - Governed Logic Unification Engine
//!
//! GLUE is Connector's canonical developer interface — a pure Rust semantic core
//! that defines one readable grammar for operating agents, memory, audit, policy,
//! protocol, and proof.

pub mod cls;
pub mod cnp;
pub mod contract;
pub mod data;
pub mod error;
pub mod handle;
pub mod infra;
pub mod intent;
pub mod noun;
pub mod print;
pub mod protocol;
pub mod result;
pub mod runtime;
pub mod selector;
pub mod session;
pub mod verb;

pub use cnp::{
    CnpCapabilityContract, CnpMessageContract, CnpPayloadKind, CnpPortContract, CnpPortDirection,
    CnpPortPermission, CnpPortType, CnpRouteContract, CnpRouteStatus, CnpSessionContract,
};
pub use contract::CompiledContract;
pub use data::{
    DataInjection, KnowledgeContract, KnowledgeQuery, KnowledgeSource, KnowledgeStorageTier,
    MemoryContract, MemoryVisibility,
};
pub use error::{ErrorCode, GlueError, GlueErrorEnvelope};
pub use handle::*;
pub use infra::{
    PipelineContract, PipelineStage, PipelineStageType, SecurityContract, ToolContract,
};
pub use intent::GlueIntent;
pub use noun::Noun;
pub use print::{
    PrintBuilder, PrintFormat, PrintOptions, PrintResult, PrintRole, PrintView, StabilityReport,
};
pub use protocol::{ProtocolAction, ProtocolContract, ProtocolKind, ProtocolMode};
pub use result::{
    EvidenceRef, GlueReceipt, GlueResult, RenderHints, ResourceInfo, ResultIntent, ResultMeta,
    ResultPresentation, ResultSummary, TrustInfo,
};
pub use selector::Selector;
pub use session::GlueSession;
pub use verb::Verb;

use std::sync::Arc;

/// The main GLUE interface
#[derive(Clone)]
pub struct Glue {
    config: Arc<GlueConfig>,
}

#[derive(Debug, Clone)]
pub struct GlueConfig {
    pub default_namespace: String,
    pub default_policy: Option<String>,
    pub audit_enabled: bool,
}

impl Default for GlueConfig {
    fn default() -> Self {
        Self {
            default_namespace: "default".into(),
            default_policy: None,
            audit_enabled: true,
        }
    }
}

impl Glue {
    pub fn new() -> Self {
        Self {
            config: Arc::new(GlueConfig::default()),
        }
    }

    pub fn with_config(config: GlueConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    // Core verbs
    pub fn run<T: Into<String>>(&self, target: T) -> handle::RunBuilder {
        handle::RunBuilder::new(self.clone(), target.into())
    }

    pub fn remember<T: Into<String>>(&self, key: T) -> handle::RememberBuilder {
        handle::RememberBuilder::new(self.clone(), key.into())
    }

    pub fn recall<T: Into<String>>(&self, query: T) -> handle::RecallBuilder {
        handle::RecallBuilder::new(self.clone(), query.into())
    }

    pub fn search<T: Into<String>>(&self, query: T) -> handle::SearchBuilder {
        handle::SearchBuilder::new(self.clone(), query.into())
    }

    pub fn list<N: Into<Noun>>(&self, noun: N) -> handle::ListBuilder {
        handle::ListBuilder::new(self.clone(), noun.into())
    }

    pub fn show<N: Into<Noun>, T: Into<String>>(&self, noun: N, target: T) -> handle::ShowBuilder {
        handle::ShowBuilder::new(self.clone(), noun.into(), target.into())
    }

    pub fn audit<T: Into<String>>(&self, target: T) -> handle::AuditBuilder {
        handle::AuditBuilder::new(self.clone(), target.into())
    }

    pub fn verify<T: Into<String>>(&self, what: T) -> handle::VerifyBuilder {
        handle::VerifyBuilder::new(self.clone(), what.into())
    }

    // Noun accessors
    pub fn agent<T: Into<String>>(&self, name: T) -> handle::AgentHandle {
        handle::AgentHandle::new(self.clone(), name.into())
    }

    pub fn memory<T: Into<String>>(&self, ns: T) -> handle::MemoryHandle {
        handle::MemoryHandle::new(self.clone(), ns.into())
    }

    pub fn knowledge<T: Into<String>>(&self, ns: T) -> handle::KnowledgeHandle {
        handle::KnowledgeHandle::new(self.clone(), ns.into())
    }

    pub fn protocol(&self, contract: ProtocolContract) -> handle::ProtocolHandle {
        handle::ProtocolHandle::new(self.clone(), contract)
    }

    pub fn cnp_session(&self, contract: CnpSessionContract) -> handle::CnpSessionHandle {
        handle::CnpSessionHandle::new(self.clone(), contract)
    }

    pub fn cnp_port(&self, contract: CnpPortContract) -> handle::CnpPortHandle {
        handle::CnpPortHandle::new(self.clone(), contract)
    }

    pub fn cnp_capability(&self, contract: CnpCapabilityContract) -> handle::CnpCapabilityHandle {
        handle::CnpCapabilityHandle::new(self.clone(), contract)
    }

    pub fn cnp_message(&self, contract: CnpMessageContract) -> handle::CnpMessageHandle {
        handle::CnpMessageHandle::new(self.clone(), contract)
    }

    pub fn cnp_route(&self, contract: CnpRouteContract) -> handle::CnpRouteHandle {
        handle::CnpRouteHandle::new(self.clone(), contract)
    }

    pub fn pipeline(&self, contract: PipelineContract) -> handle::PipelineHandle {
        handle::PipelineHandle::new(self.clone(), contract)
    }

    pub fn tool<T: Into<String>>(&self, name: T) -> handle::ToolHandle {
        handle::ToolHandle::new(self.clone(), name.into())
    }

    pub fn policy<T: Into<String>>(&self, name: T) -> handle::PolicyHandle {
        handle::PolicyHandle::new(self.clone(), name.into())
    }

    pub fn session(&self) -> handle::SessionBuilder {
        handle::SessionBuilder::new(self.clone())
    }

    pub fn config(&self) -> &GlueConfig {
        &self.config
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Print API — Direct SOE surface access
    // ═══════════════════════════════════════════════════════════════════════

    /// Print a surface using verb+noun grammar
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let g = glue();
    ///
    /// // Show agent state
    /// let surface = g.print(Verb::Show, Noun::Agent, "claims-001")?.execute()?;
    /// println!("{}", surface);
    ///
    /// // Audit with JSON output
    /// let audit = g.print(Verb::Audit, Noun::Agent, "claims-001")?.json().execute()?;
    ///
    /// // Forensic view
    /// let debug = g.print(Verb::Show, Noun::Agent, "claims-001")?.forensic().execute()?;
    /// ```
    pub fn print<T: Into<String>>(&self, verb: Verb, noun: Noun, target: T) -> print::PrintBuilder {
        print::PrintBuilder::new(verb, noun, target)
    }

    /// Self-surveillance: agent inspects its own state
    pub fn self_inspect<T: Into<String>>(&self, agent_pid: T) -> print::PrintBuilder {
        print::PrintBuilder::new(Verb::Show, Noun::Agent, agent_pid)
    }

    /// Self-audit: agent audits its own actions
    pub fn self_audit<T: Into<String>>(&self, agent_pid: T) -> print::PrintBuilder {
        print::PrintBuilder::new(Verb::Audit, Noun::Agent, agent_pid)
    }

    /// Stability check: comprehensive self-surveillance
    pub fn stability<T: Into<String> + Clone>(
        &self,
        agent_pid: T,
    ) -> Result<print::StabilityReport, error::GlueError> {
        let health = self.self_inspect(agent_pid.clone()).execute()?;
        let audit = self.self_audit(agent_pid.clone()).execute()?;

        Ok(print::StabilityReport {
            agent_pid: agent_pid.into(),
            health,
            audit,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        })
    }
}

impl Default for Glue {
    fn default() -> Self {
        Self::new()
    }
}

/// Global glue instance helper
pub fn glue() -> Glue {
    Glue::new()
}
