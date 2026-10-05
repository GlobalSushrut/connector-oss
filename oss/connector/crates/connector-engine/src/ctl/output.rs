//! Output System — Reading a System Report, Not Terminal Noise
//!
//! ConnectorCTL output should feel like reading a system report.
//!
//! Output Modes:
//! 1. Default (Readable View) — Clean, human-readable
//! 2. JSON — Machine-readable
//! 3. Book Mode — Narrative audit/trace/investigation reports

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Output Mode — How to render output
// ═══════════════════════════════════════════════════════════════

/// Output mode for ConnectorCTL commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    /// Default readable view (clean, high signal)
    Default,

    /// JSON output for machine consumption
    Json,

    /// Book mode — narrative report format
    /// Used for: audit, trace, investigation, compliance
    Book,

    /// Compact single-line output
    Compact,

    /// Wide output (more columns)
    Wide,

    /// Quiet mode (minimal output)
    Quiet,

    /// Verbose mode (detailed output)
    Verbose,
}

impl Default for OutputMode {
    fn default() -> Self {
        Self::Default
    }
}

impl OutputMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Json => "json",
            Self::Book => "book",
            Self::Compact => "compact",
            Self::Wide => "wide",
            Self::Quiet => "quiet",
            Self::Verbose => "verbose",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "default" => Some(Self::Default),
            "json" => Some(Self::Json),
            "book" => Some(Self::Book),
            "compact" => Some(Self::Compact),
            "wide" => Some(Self::Wide),
            "quiet" | "q" => Some(Self::Quiet),
            "verbose" | "v" => Some(Self::Verbose),
            _ => None,
        }
    }

    /// Check if this mode produces machine-readable output
    pub fn is_machine_readable(&self) -> bool {
        matches!(self, Self::Json)
    }

    /// Check if this mode is a narrative format
    pub fn is_narrative(&self) -> bool {
        matches!(self, Self::Book)
    }
}

// ═══════════════════════════════════════════════════════════════
// Output Format — File format for exports
// ═══════════════════════════════════════════════════════════════

/// Output format for exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// JSON format
    Json,

    /// Markdown format
    Markdown,

    /// PDF format
    Pdf,

    /// HTML format
    Html,

    /// CSV format
    Csv,

    /// YAML format
    Yaml,

    /// Plain text
    Text,

    /// Bundle (zip with multiple files)
    Bundle,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Json
    }
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Pdf => "pdf",
            Self::Html => "html",
            Self::Csv => "csv",
            Self::Yaml => "yaml",
            Self::Text => "text",
            Self::Bundle => "bundle",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "md",
            Self::Pdf => "pdf",
            Self::Html => "html",
            Self::Csv => "csv",
            Self::Yaml => "yaml",
            Self::Text => "txt",
            Self::Bundle => "zip",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "markdown" | "md" => Some(Self::Markdown),
            "pdf" => Some(Self::Pdf),
            "html" => Some(Self::Html),
            "csv" => Some(Self::Csv),
            "yaml" | "yml" => Some(Self::Yaml),
            "text" | "txt" => Some(Self::Text),
            "bundle" | "zip" => Some(Self::Bundle),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Output View — Level of detail
// ═══════════════════════════════════════════════════════════════

/// View level for output detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputView {
    /// Summary view — clean, high signal (default)
    Summary,

    /// Ops view — operational metrics
    Ops,

    /// Forensic view — full evidence chain
    Forensic,

    /// Exec view — business storytelling
    Exec,
}

impl Default for OutputView {
    fn default() -> Self {
        Self::Summary
    }
}

impl OutputView {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Ops => "ops",
            Self::Forensic => "forensic",
            Self::Exec => "exec",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "summary" => Some(Self::Summary),
            "ops" => Some(Self::Ops),
            "forensic" => Some(Self::Forensic),
            "exec" => Some(Self::Exec),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Output Options — Combined output configuration
// ═══════════════════════════════════════════════════════════════

/// Combined output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputOptions {
    /// Output mode
    pub mode: OutputMode,

    /// View level
    pub view: OutputView,

    /// Export format (for export commands)
    pub format: Option<OutputFormat>,

    /// Output file path (for exports)
    pub output_path: Option<String>,

    /// Whether to include timestamps
    pub timestamps: bool,

    /// Whether to include colors
    pub colors: bool,

    /// Whether to include links
    pub links: bool,

    /// Maximum width (0 = auto)
    pub max_width: u32,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            mode: OutputMode::Default,
            view: OutputView::Summary,
            format: None,
            output_path: None,
            timestamps: true,
            colors: true,
            links: true,
            max_width: 0,
        }
    }
}

impl OutputOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn json() -> Self {
        Self {
            mode: OutputMode::Json,
            colors: false,
            links: false,
            ..Self::default()
        }
    }

    pub fn book() -> Self {
        Self {
            mode: OutputMode::Book,
            view: OutputView::Forensic,
            ..Self::default()
        }
    }

    pub fn with_mode(mut self, mode: OutputMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_view(mut self, view: OutputView) -> Self {
        self.view = view;
        self
    }

    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = Some(format);
        self
    }

    pub fn with_output_path(mut self, path: impl Into<String>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    pub fn no_colors(mut self) -> Self {
        self.colors = false;
        self
    }

    pub fn no_links(mut self) -> Self {
        self.links = false;
        self
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_mode_parse() {
        assert_eq!(OutputMode::parse("json"), Some(OutputMode::Json));
        assert_eq!(OutputMode::parse("BOOK"), Some(OutputMode::Book));
        assert_eq!(OutputMode::parse("q"), Some(OutputMode::Quiet));
    }

    #[test]
    fn test_output_format_extension() {
        assert_eq!(OutputFormat::Json.extension(), "json");
        assert_eq!(OutputFormat::Markdown.extension(), "md");
        assert_eq!(OutputFormat::Pdf.extension(), "pdf");
    }

    #[test]
    fn test_output_view_parse() {
        assert_eq!(OutputView::parse("summary"), Some(OutputView::Summary));
        assert_eq!(OutputView::parse("forensic"), Some(OutputView::Forensic));
    }

    #[test]
    fn test_output_options_builder() {
        let opts = OutputOptions::new()
            .with_mode(OutputMode::Book)
            .with_view(OutputView::Forensic)
            .no_colors();

        assert_eq!(opts.mode, OutputMode::Book);
        assert_eq!(opts.view, OutputView::Forensic);
        assert!(!opts.colors);
    }
}
