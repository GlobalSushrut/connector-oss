//! GLUE Printer — Direct SOE access via glue.print(verb, noun)
//!
//! Bridges GLUE's verb+noun grammar to SOE's SurfaceEngine for programmatic
//! surface rendering. Enables self-surveillance, stability monitoring, and
//! internal observability directly in code.
//!
//! # Motivation
//!
//! LLM-based agents need internal observability for:
//! - Self-surveillance (monitoring own state)
//! - Stability analysis (detecting degradation)
//! - Internal debugging (understanding own behavior)
//! - Proof generation (verifiable outputs)
//!
//! Instead of raw logs, agents can use structured surfaces:
//!
//! ```rust,ignore
//! use connector_engine::surface::glue_printer::GluePrinter;
//!
//! let printer = GluePrinter::new();
//!
//! // Self-surveillance: agent inspects its own state
//! let surface = printer.print("show", "agent", "self")?;
//!
//! // Stability check: monitor health metrics
//! let health = printer.print("health", "agent", "claims-001")?;
//!
//! // Audit trail: verify own actions
//! let audit = printer.print("audit", "agent", "claims-001")?;
//!
//! // Pipeline status: check data flow
//! let pipeline = printer.print("show", "pipeline", "ingestion-001")?;
//! ```

use super::*;
use super::engine::{SurfaceEngine, RenderRequest, RenderResult, RenderError, EngineConfig};
use super::document::{SurfaceType, SurfaceView};
use super::roles::Role;
use super::time::SurfaceTimeSelector;
use super::export::ExportFormat;
use serde::{Deserialize, Serialize};

/// GLUE Printer — programmatic SOE access
pub struct GluePrinter {
    engine: SurfaceEngine,
    config: PrinterConfig,
}

#[derive(Debug, Clone)]
pub struct PrinterConfig {
    pub default_role: Role,
    pub default_view: SurfaceView,
    pub default_format: OutputFormat,
    pub actor: String,
    pub namespace: Option<String>,
}

impl Default for PrinterConfig {
    fn default() -> Self {
        Self {
            default_role: Role::Developer,
            default_view: SurfaceView::Ops,
            default_format: OutputFormat::Terminal,
            actor: "glue".into(),
            namespace: None,
        }
    }
}

/// Output format for printed surfaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// ANSI terminal output
    Terminal,
    /// JSON structured output
    Json,
    /// Markdown documentation
    Markdown,
    /// Raw SurfaceDocument
    Raw,
}

/// Printed surface result
#[derive(Debug, Clone)]
pub struct PrintedSurface {
    pub output: String,
    pub format: OutputFormat,
    pub cid: String,
    pub tier: String,
    pub render_time_ms: u64,
}

impl PrintedSurface {
    pub fn as_str(&self) -> &str {
        &self.output
    }
}

impl std::fmt::Display for PrintedSurface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.output)
    }
}

/// Error from print operation
#[derive(Debug, Clone)]
pub enum PrintError {
    UnknownVerb(String),
    UnknownNoun(String),
    RenderFailed(String),
    PolicyDenied(String),
}

impl std::fmt::Display for PrintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVerb(v) => write!(f, "Unknown verb: {}", v),
            Self::UnknownNoun(n) => write!(f, "Unknown noun: {}", n),
            Self::RenderFailed(e) => write!(f, "Render failed: {}", e),
            Self::PolicyDenied(e) => write!(f, "Policy denied: {}", e),
        }
    }
}

impl Default for GluePrinter {
    fn default() -> Self { Self::new() }
}

impl GluePrinter {
    pub fn new() -> Self {
        Self {
            engine: SurfaceEngine::default(),
            config: PrinterConfig::default(),
        }
    }

    pub fn with_config(config: PrinterConfig) -> Self {
        Self {
            engine: SurfaceEngine::new(EngineConfig::default()),
            config,
        }
    }

    pub fn with_engine(engine: SurfaceEngine, config: PrinterConfig) -> Self {
        Self { engine, config }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Core print API
    // ═══════════════════════════════════════════════════════════════════════

    /// Print a surface using verb+noun grammar
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let printer = GluePrinter::new();
    ///
    /// // Show agent state
    /// printer.print("show", "agent", "claims-001")?;
    ///
    /// // Audit agent actions
    /// printer.print("audit", "agent", "claims-001")?;
    ///
    /// // Verify proof chain
    /// printer.print("verify", "proof", "rcpt-001")?;
    ///
    /// // Monitor pipeline
    /// printer.print("monitor", "pipeline", "ingestion-001")?;
    /// ```
    pub fn print(&mut self, verb: &str, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print_with_options(verb, noun, target, PrintOptions::default())
    }

    /// Print with custom options
    pub fn print_with_options(
        &mut self,
        verb: &str,
        noun: &str,
        target: &str,
        options: PrintOptions,
    ) -> Result<PrintedSurface, PrintError> {
        let surface_type = self.verb_noun_to_surface(verb, noun)?;
        let view = options.view.unwrap_or(self.config.default_view);
        let role = options.role.unwrap_or(self.config.default_role);
        let format = options.format.unwrap_or(self.config.default_format);

        let request = RenderRequest::new(surface_type, target, &self.config.actor, role)
            .view(view)
            .time(options.time.unwrap_or(SurfaceTimeSelector::Now));

        let result = self.engine.render(request).map_err(|e| match e {
            RenderError::PolicyDenied(g) => PrintError::PolicyDenied(format!("{:?}", g)),
            RenderError::ContractViolation { errors, warnings } => PrintError::RenderFailed(format!(
                "surface contract violation — errors: {:?}; warnings: {:?}",
                errors, warnings
            )),
            _ => PrintError::RenderFailed(format!("{e}")),
        })?;

        let output = match format {
            OutputFormat::Terminal => result.to_terminal(),
            OutputFormat::Json => result.to_json(),
            OutputFormat::Markdown => result.export(ExportFormat::Markdown),
            OutputFormat::Raw => serde_json::to_string_pretty(result.document()).unwrap_or_default(),
        };

        Ok(PrintedSurface {
            output,
            format,
            cid: result.cid().to_string(),
            tier: format!("{:?}", result.tier()),
            render_time_ms: result.render_time_ms,
        })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Convenience methods (verb-specific)
    // ═══════════════════════════════════════════════════════════════════════

    /// Show a resource
    pub fn show(&mut self, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print("show", noun, target)
    }

    /// Audit a resource
    pub fn audit(&mut self, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print("audit", noun, target)
    }

    /// Verify a resource
    pub fn verify(&mut self, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print("verify", noun, target)
    }

    /// Health check
    pub fn health(&mut self, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print("health", noun, target)
    }

    /// Debug a resource
    pub fn debug(&mut self, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print("debug", noun, target)
    }

    /// Trace a resource
    pub fn trace(&mut self, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print("trace", noun, target)
    }

    /// Monitor a resource
    pub fn monitor(&mut self, noun: &str, target: &str) -> Result<PrintedSurface, PrintError> {
        self.print("monitor", noun, target)
    }

    /// List resources
    pub fn list(&mut self, noun: &str) -> Result<PrintedSurface, PrintError> {
        self.print("list", noun, "*")
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Self-surveillance methods (for LLM agents)
    // ═══════════════════════════════════════════════════════════════════════

    /// Self-inspect: agent inspects its own state
    pub fn self_inspect(&mut self, agent_pid: &str) -> Result<PrintedSurface, PrintError> {
        self.show("agent", agent_pid)
    }

    /// Self-health: agent checks its own health
    pub fn self_health(&mut self, agent_pid: &str) -> Result<PrintedSurface, PrintError> {
        self.health("agent", agent_pid)
    }

    /// Self-audit: agent audits its own actions
    pub fn self_audit(&mut self, agent_pid: &str) -> Result<PrintedSurface, PrintError> {
        self.audit("agent", agent_pid)
    }

    /// Self-trace: agent traces its own execution
    pub fn self_trace(&mut self, agent_pid: &str) -> Result<PrintedSurface, PrintError> {
        self.trace("agent", agent_pid)
    }

    /// Stability check: comprehensive self-surveillance
    pub fn stability_check(&mut self, agent_pid: &str) -> Result<StabilityReport, PrintError> {
        let health = self.self_health(agent_pid)?;
        let audit = self.self_audit(agent_pid)?;
        
        Ok(StabilityReport {
            agent_pid: agent_pid.to_string(),
            health_surface: health,
            audit_surface: audit,
            timestamp: chrono::Utc::now().timestamp_millis(),
        })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Distributed network methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Show network topology
    pub fn network(&mut self) -> Result<PrintedSurface, PrintError> {
        self.print("show", "network", "global")
    }

    /// Show agent location
    pub fn location(&mut self, agent_pid: &str) -> Result<PrintedSurface, PrintError> {
        self.print("show", "location", agent_pid)
    }

    /// Show sandbox state
    pub fn sandbox(&mut self, agent_pid: &str) -> Result<PrintedSurface, PrintError> {
        self.print("show", "sandbox", agent_pid)
    }

    /// Show lifecycle trace
    pub fn lifecycle(&mut self, agent_pid: &str) -> Result<PrintedSurface, PrintError> {
        self.print("show", "lifecycle", agent_pid)
    }

    /// Show pipeline execution
    pub fn pipeline(&mut self, pipeline_id: &str) -> Result<PrintedSurface, PrintError> {
        self.print("show", "pipeline", pipeline_id)
    }

    /// Show coordination session
    pub fn coordination(&mut self, session_id: &str) -> Result<PrintedSurface, PrintError> {
        self.print("show", "coordination", session_id)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal routing
    // ═══════════════════════════════════════════════════════════════════════

    fn verb_noun_to_surface(&self, verb: &str, noun: &str) -> Result<SurfaceType, PrintError> {
        let v = verb.to_lowercase();
        let n = noun.to_lowercase();

        match (v.as_str(), n.as_str()) {
            // Agent surfaces
            ("show" | "inspect", "agent") => Ok(SurfaceType::Agent),
            ("health", "agent") => Ok(SurfaceType::Health),
            ("debug", "agent") => Ok(SurfaceType::Debug),
            ("trace", "agent") => Ok(SurfaceType::Trace),
            ("audit", "agent") => Ok(SurfaceType::Audit),

            // Memory surfaces
            ("show" | "inspect", "memory") => Ok(SurfaceType::Memory),
            ("audit", "memory") => Ok(SurfaceType::Audit),

            // Knowledge surfaces
            ("show" | "inspect", "knowledge") => Ok(SurfaceType::Knowledge),

            // Compliance surfaces
            ("show" | "inspect", "compliance") => Ok(SurfaceType::Compliance),
            ("compliance", _) => Ok(SurfaceType::Compliance),

            // Proof surfaces
            ("verify", _) => Ok(SurfaceType::Proof),
            ("show" | "inspect", "proof") => Ok(SurfaceType::Proof),

            // Books surfaces
            ("show" | "inspect", "books" | "ledger") => Ok(SurfaceType::Books),
            ("books" | "ledger", _) => Ok(SurfaceType::Books),

            // Tool surfaces
            ("show" | "inspect", "tool") => Ok(SurfaceType::Tool),

            // Policy surfaces
            ("show" | "inspect", "policy") => Ok(SurfaceType::Policy),

            // Contract surfaces
            ("show" | "inspect", "contract") => Ok(SurfaceType::Contract),

            // Monitor surfaces
            ("monitor" | "watch", _) => Ok(SurfaceType::Monitor),

            // Distributed network surfaces
            ("show" | "inspect", "network") => Ok(SurfaceType::Monitor),
            ("show" | "inspect", "sandbox") => Ok(SurfaceType::Agent),
            ("show" | "inspect", "lifecycle") => Ok(SurfaceType::Trace),
            ("show" | "inspect", "pipeline") => Ok(SurfaceType::Trace),
            ("show" | "inspect", "coordination") => Ok(SurfaceType::Trace),
            ("show" | "inspect", "location") => Ok(SurfaceType::Agent),

            // List surfaces
            ("list", _) => Ok(SurfaceType::Inspect),

            // Explain surfaces
            ("explain", _) => Ok(SurfaceType::Explain),

            // Review surfaces
            ("review", _) => Ok(SurfaceType::Review),

            // Default fallback
            ("show" | "inspect", _) => Ok(SurfaceType::Inspect),
            (_, _) => Err(PrintError::UnknownVerb(verb.to_string())),
        }
    }

    /// Get engine reference for advanced usage
    pub fn engine(&self) -> &SurfaceEngine {
        &self.engine
    }

    /// Get mutable engine reference
    pub fn engine_mut(&mut self) -> &mut SurfaceEngine {
        &mut self.engine
    }
}

/// Print options for customization
#[derive(Debug, Clone, Default)]
pub struct PrintOptions {
    pub view: Option<SurfaceView>,
    pub role: Option<Role>,
    pub format: Option<OutputFormat>,
    pub time: Option<SurfaceTimeSelector>,
}

impl PrintOptions {
    pub fn new() -> Self { Self::default() }
    pub fn view(mut self, view: SurfaceView) -> Self { self.view = Some(view); self }
    pub fn role(mut self, role: Role) -> Self { self.role = Some(role); self }
    pub fn format(mut self, format: OutputFormat) -> Self { self.format = Some(format); self }
    pub fn time(mut self, time: SurfaceTimeSelector) -> Self { self.time = Some(time); self }
}

/// Stability report for self-surveillance
#[derive(Debug, Clone)]
pub struct StabilityReport {
    pub agent_pid: String,
    pub health_surface: PrintedSurface,
    pub audit_surface: PrintedSurface,
    pub timestamp: i64,
}

impl StabilityReport {
    pub fn is_healthy(&self) -> bool {
        // Simple heuristic: check if health output contains "HEALTHY"
        self.health_surface.output.contains("HEALTHY")
    }

    pub fn summary(&self) -> String {
        format!(
            "Stability Report for {}\n  Health: {}\n  Audit CID: {}\n  Timestamp: {}",
            self.agent_pid,
            if self.is_healthy() { "OK" } else { "DEGRADED" },
            self.audit_surface.cid,
            self.timestamp
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global convenience function
// ═══════════════════════════════════════════════════════════════════════════

/// Create a new GluePrinter instance
pub fn printer() -> GluePrinter {
    GluePrinter::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glue_printer_show() {
        let mut printer = GluePrinter::new();
        let result = printer.show("agent", "test-001");
        assert!(result.is_ok());
        let surface = result.unwrap();
        assert!(!surface.cid.is_empty());
    }

    #[test]
    fn test_glue_printer_audit() {
        let mut printer = GluePrinter::new();
        let result = printer.audit("agent", "test-001");
        assert!(result.is_ok());
    }

    #[test]
    fn test_glue_printer_self_surveillance() {
        let mut printer = GluePrinter::new();
        let result = printer.stability_check("test-001");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.agent_pid, "test-001");
    }

    #[test]
    fn test_verb_noun_routing() {
        let printer = GluePrinter::new();
        assert_eq!(printer.verb_noun_to_surface("show", "agent").unwrap(), SurfaceType::Agent);
        assert_eq!(printer.verb_noun_to_surface("audit", "agent").unwrap(), SurfaceType::Audit);
        assert_eq!(printer.verb_noun_to_surface("verify", "proof").unwrap(), SurfaceType::Proof);
        assert_eq!(printer.verb_noun_to_surface("monitor", "pipeline").unwrap(), SurfaceType::Monitor);
    }

    #[test]
    fn test_print_options() {
        let mut printer = GluePrinter::new();
        let options = PrintOptions::new()
            .view(SurfaceView::Forensic)
            .format(OutputFormat::Json);
        let result = printer.print_with_options("show", "agent", "test-001", options);
        assert!(result.is_ok());
        let surface = result.unwrap();
        assert_eq!(surface.format, OutputFormat::Json);
    }
}
