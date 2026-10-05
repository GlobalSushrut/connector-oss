//! GLUE Print — Direct SOE surface access via glue.print()
//!
//! Enables programmatic surface rendering from GLUE code for:
//! - Self-surveillance (agents monitoring own state)
//! - Stability analysis (detecting degradation)
//! - Internal debugging (understanding behavior)
//! - Proof generation (verifiable outputs)
//!
//! # Usage
//!
//! ```rust,ignore
//! use connector_glue::{glue, Verb, Noun};
//!
//! let g = glue();
//!
//! // Print agent surface
//! let surface = g.print(Verb::Show, Noun::Agent, "claims-001")?;
//! println!("{}", surface);
//!
//! // Self-surveillance
//! let health = g.print(Verb::Show, Noun::Agent, "self")?.health();
//!
//! // Stability check
//! let report = g.stability("claims-001")?;
//! if !report.is_healthy() {
//!     // Take corrective action
//! }
//! ```

use crate::{Verb, Noun, GlueError};
use serde::{Deserialize, Serialize};

/// Output format for printed surfaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrintFormat {
    /// ANSI terminal output (default)
    #[default]
    Terminal,
    /// Semantic packaged JSON output
    Json,
    /// Markdown documentation
    Markdown,
    /// Raw surface document
    Raw,
}

/// View mode for surfaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrintView {
    /// Summary view
    Summary,
    /// Operational view (default)
    #[default]
    Ops,
    /// Forensic/detailed view
    Forensic,
    /// Executive view
    Exec,
}

/// Role for surface rendering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrintRole {
    /// Developer role (default)
    #[default]
    Developer,
    /// Operator role
    Operator,
    /// Auditor role
    Auditor,
    /// Executive role
    Executive,
}

/// Print options for customization
#[derive(Debug, Clone, Default)]
pub struct PrintOptions {
    pub format: PrintFormat,
    pub view: PrintView,
    pub role: PrintRole,
    pub time_selector: Option<String>,
}

impl PrintOptions {
    pub fn new() -> Self { Self::default() }
    pub fn format(mut self, f: PrintFormat) -> Self { self.format = f; self }
    pub fn view(mut self, v: PrintView) -> Self { self.view = v; self }
    pub fn role(mut self, r: PrintRole) -> Self { self.role = r; self }
    pub fn at(mut self, time: impl Into<String>) -> Self { self.time_selector = Some(time.into()); self }
}

/// Printed surface result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintResult {
    /// Rendered output string
    pub output: String,
    /// Content identifier (CID) for this surface
    pub cid: String,
    /// Trust tier of the data
    pub tier: String,
    /// Render time in milliseconds
    pub render_time_ms: u64,
    /// Format used
    pub format: PrintFormat,
    /// Verb used
    pub verb: String,
    /// Noun used
    pub noun: String,
    /// Target resource
    pub target: String,
}

impl PrintResult {
    /// Get output as string
    pub fn as_str(&self) -> &str {
        &self.output
    }

    /// Check if output indicates healthy state
    pub fn is_healthy(&self) -> bool {
        self.output.contains("HEALTHY") || self.output.contains("✓")
    }

    /// Check if output indicates degraded state
    pub fn is_degraded(&self) -> bool {
        self.output.contains("DEGRADED") || self.output.contains("WARN")
    }

    /// Check if output indicates failed state
    pub fn is_failed(&self) -> bool {
        self.output.contains("FAILED") || self.output.contains("ERROR") || self.output.contains("CRITICAL")
    }

    /// Get the CID for verification
    pub fn cid(&self) -> &str {
        &self.cid
    }
}

impl std::fmt::Display for PrintResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.output)
    }
}

/// Stability report for self-surveillance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabilityReport {
    pub agent_pid: String,
    pub health: PrintResult,
    pub audit: PrintResult,
    pub timestamp: i64,
}

impl StabilityReport {
    pub fn is_healthy(&self) -> bool {
        self.health.is_healthy() && !self.audit.is_failed()
    }

    pub fn summary(&self) -> String {
        format!(
            "Stability: {} | Health CID: {} | Audit CID: {}",
            if self.is_healthy() { "OK" } else { "DEGRADED" },
            self.health.cid,
            self.audit.cid
        )
    }
}

/// Print builder for fluent API
pub struct PrintBuilder {
    verb: Verb,
    noun: Noun,
    target: String,
    options: PrintOptions,
}

impl PrintBuilder {
    pub fn new(verb: Verb, noun: Noun, target: impl Into<String>) -> Self {
        Self {
            verb,
            noun,
            target: target.into(),
            options: PrintOptions::default(),
        }
    }

    pub fn format(mut self, f: PrintFormat) -> Self {
        self.options.format = f;
        self
    }

    pub fn view(mut self, v: PrintView) -> Self {
        self.options.view = v;
        self
    }

    pub fn role(mut self, r: PrintRole) -> Self {
        self.options.role = r;
        self
    }

    pub fn at(mut self, time: impl Into<String>) -> Self {
        self.options.time_selector = Some(time.into());
        self
    }

    pub fn json(self) -> Self {
        self.format(PrintFormat::Json)
    }

    pub fn markdown(self) -> Self {
        self.format(PrintFormat::Markdown)
    }

    pub fn forensic(self) -> Self {
        self.view(PrintView::Forensic)
    }

    pub fn summary(self) -> Self {
        self.view(PrintView::Summary)
    }

    /// Execute the print and return result by routing through the real `GluePrinter`.
    pub fn execute(self) -> Result<PrintResult, GlueError> {
        use connector_engine::surface::glue_printer::{GluePrinter, PrintOptions as EngineOptions, OutputFormat};
        use connector_engine::surface::document::SurfaceView;
        use connector_engine::surface::roles::Role;
        use connector_engine::surface::time::SurfaceTimeSelector;

        let engine_view = match self.options.view {
            PrintView::Summary  => SurfaceView::Summary,
            PrintView::Ops      => SurfaceView::Ops,
            PrintView::Forensic => SurfaceView::Forensic,
            PrintView::Exec     => SurfaceView::Exec,
        };
        let engine_role = match self.options.role {
            PrintRole::Developer => Role::Developer,
            PrintRole::Operator  => Role::Operator,
            PrintRole::Auditor   => Role::Auditor,
            PrintRole::Executive => Role::Executive,
        };
        let engine_format = match self.options.format {
            PrintFormat::Terminal => OutputFormat::Terminal,
            PrintFormat::Json     => OutputFormat::Json,
            PrintFormat::Markdown => OutputFormat::Markdown,
            PrintFormat::Raw      => OutputFormat::Raw,
        };
        let engine_time = self.options.time_selector.as_deref()
            .and_then(|s| SurfaceTimeSelector::parse(s))
            .unwrap_or(SurfaceTimeSelector::Now);

        let mut printer = GluePrinter::new();
        let eng_options = EngineOptions::new()
            .view(engine_view)
            .role(engine_role)
            .format(engine_format)
            .time(engine_time);

        let verb = self.verb.as_str().to_string();
        let noun = self.noun.as_str().to_string();
        let target = self.target.clone();
        let format = self.options.format;

        printer
            .print_with_options(&verb, &noun, &target, eng_options)
            .map(|r| PrintResult {
                output: r.output,
                cid: r.cid,
                tier: r.tier,
                render_time_ms: r.render_time_ms,
                format,
                verb,
                noun,
                target,
            })
            .map_err(|e| GlueError::new(
                crate::error::ErrorCode::InternalError,
                format!("{}", e),
            ))
    }
}

/// Convenience functions for common print operations
pub mod shortcuts {
    use super::*;

    /// Show agent surface
    pub fn show_agent(target: &str) -> PrintBuilder {
        PrintBuilder::new(Verb::Show, Noun::Agent, target)
    }

    /// Show memory surface
    pub fn show_memory(target: &str) -> PrintBuilder {
        PrintBuilder::new(Verb::Show, Noun::Memory, target)
    }

    /// Audit agent
    pub fn audit_agent(target: &str) -> PrintBuilder {
        PrintBuilder::new(Verb::Audit, Noun::Agent, target)
    }

    /// Verify proof
    pub fn verify_proof(target: &str) -> PrintBuilder {
        PrintBuilder::new(Verb::Verify, Noun::Proof, target)
    }

    /// List agents
    pub fn list_agents() -> PrintBuilder {
        PrintBuilder::new(Verb::List, Noun::Agent, "*")
    }

    /// List contracts
    pub fn list_contracts() -> PrintBuilder {
        PrintBuilder::new(Verb::List, Noun::Contract, "*")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_builder() {
        let result = PrintBuilder::new(Verb::Show, Noun::Agent, "test-001")
            .json()
            .forensic()
            .execute();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.format, PrintFormat::Json);
        assert!(!r.cid.is_empty());
        assert!(!r.output.is_empty());
    }

    #[test]
    fn test_shortcuts() {
        let result = shortcuts::show_agent("claims-001").execute();
        assert!(result.is_ok());
        assert!(!result.unwrap().cid.is_empty());
    }

    #[test]
    fn test_print_result_health_check() {
        let healthy = PrintResult {
            output: "Status: HEALTHY".into(),
            cid: "test".into(),
            tier: "T1".into(),
            render_time_ms: 1,
            format: PrintFormat::Terminal,
            verb: "show".into(),
            noun: "agent".into(),
            target: "test".into(),
        };
        assert!(healthy.is_healthy());
        assert!(!healthy.is_failed());
    }
}
