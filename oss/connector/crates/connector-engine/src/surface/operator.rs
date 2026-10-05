//! Operator Surface — The unified "connectorctl status" entry point
//!
//! Implements the 3-step output rule with clickable drill-down:
//! 1. Status (1 line)
//! 2. Problem (1-2 lines)  
//! 3. Action (1 line)
//!
//! Everything else is collapsible/clickable for deeper inspection.

use super::document::*;
use super::signal::*;
use super::intelligence::*;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// Operator Output — The final rendered output for operators
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorOutput {
    /// The extracted signal
    pub signal: Signal,
    /// Human narrative
    pub narrative: String,
    /// Clickable drill-down paths
    pub drill_downs: Vec<DrillDown>,
    /// Output mode
    pub mode: OutputMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutputMode {
    /// 3 lines: Status/Problem/Action
    Compact,
    /// 5-7 lines: + Impact/Delta
    #[default]
    Summary,
    /// Full signal with all blocks
    Full,
    /// Human narrative paragraph
    Narrative,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrillDown {
    pub label: String,
    pub command: String,
    pub depth: u8,
}

impl OperatorOutput {
    pub fn render(&self) -> String {
        match self.mode {
            OutputMode::Compact => self.render_compact(),
            OutputMode::Summary => self.render_summary(),
            OutputMode::Full => self.render_full(),
            OutputMode::Narrative => self.narrative.clone(),
        }
    }

    fn render_compact(&self) -> String {
        self.signal.compact()
    }

    fn render_summary(&self) -> String {
        let mut lines = vec![self.signal.summary()];
        if !self.drill_downs.is_empty() {
            lines.push("  DRILL DOWN:".into());
            for dd in &self.drill_downs {
                lines.push(format!("    [{}] {}", dd.label, dd.command));
            }
        }
        lines.join("\n")
    }

    fn render_full(&self) -> String {
        let mut lines = vec![
            self.signal.summary(),
            "".into(),
            "NARRATIVE:".into(),
            format!("  {}", self.narrative),
        ];
        if !self.drill_downs.is_empty() {
            lines.push("".into());
            lines.push("DRILL DOWN:".into());
            for dd in &self.drill_downs {
                let indent = "  ".repeat(dd.depth as usize + 1);
                lines.push(format!("{}[{}] {}", indent, dd.label, dd.command));
            }
        }
        lines.join("\n")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Operator Engine — Transforms surfaces into operator output
// ═══════════════════════════════════════════════════════════════════════════

pub struct OperatorEngine;

impl OperatorEngine {
    /// Transform a surface document into operator output
    pub fn transform(doc: &SurfaceDocument, mode: OutputMode) -> OperatorOutput {
        let signal = SignalExtractor::extract(doc);
        let narrative = Narrator::narrate(&signal);
        let drill_downs = Self::build_drill_downs(doc);

        OperatorOutput { signal, narrative, drill_downs, mode }
    }

    /// Build drill-down paths for deeper inspection, prioritizing product-focused commands.
    fn build_drill_downs(doc: &SurfaceDocument) -> Vec<DrillDown> {
        let mut dds = vec![];
        let base = &doc.header.subject.inspect;

        // --- Primary, Product-Focused Commands ---
        dds.push(DrillDown {
            label: "Explain".into(),
            command: format!("connectorctl explain {}", base),
            depth: 0,
        });
        dds.push(DrillDown {
            label: "Risk".into(),
            command: format!("connectorctl risk {}", base),
            depth: 0,
        });
        dds.push(DrillDown {
            label: "Prove".into(),
            command: format!("connectorctl prove {}", base),
            depth: 0,
        });
        dds.push(DrillDown {
            label: "Cost".into(),
            command: format!("connectorctl cost {}", base),
            depth: 0,
        });

        // --- Secondary, Technical Commands ---
        dds.push(DrillDown {
            label: "Inspect Deeply".into(),
            command: format!("connectorctl inspect {} --deep", base),
            depth: 1,
        });
        dds.push(DrillDown {
            label: "Trace Forensically".into(),
            command: format!("connectorctl trace {} --forensic", base),
            depth: 1,
        });

        dds
    }

    /// Build unified status output across multiple surfaces
    pub fn status(docs: &[SurfaceDocument]) -> String {
        let signals: Vec<Signal> = docs.iter().map(|d| SignalExtractor::extract(d)).collect();
        let health = GlobalHealth::from_signals(&signals);
        health.render()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Quick Status — The "connectorctl status" command
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickStatus {
    pub line: String,
    pub emoji: &'static str,
    pub level: StatusLevel,
    pub drill_down: String,
}

impl QuickStatus {
    /// Generate quick status from a surface
    pub fn from_surface(doc: &SurfaceDocument) -> Self {
        let signal = SignalExtractor::extract(doc);
        Self {
            line: signal.status.state.clone(),
            emoji: signal.status.level.emoji(),
            level: signal.status.level,
            drill_down: signal.drill_down,
        }
    }

    /// Render as single line
    pub fn render(&self) -> String {
        format!("{} {} | {}", self.emoji, self.line, self.drill_down)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// View Modes — Summary/Ops/Forensic compression
// ═══════════════════════════════════════════════════════════════════════════

pub struct ViewCompressor;

impl ViewCompressor {
    /// Compress surface to summary view (5-7 lines)
    pub fn summary(doc: &SurfaceDocument) -> String {
        OperatorEngine::transform(doc, OutputMode::Summary).render()
    }

    /// Compress surface to compact view (3 lines)
    pub fn compact(doc: &SurfaceDocument) -> String {
        OperatorEngine::transform(doc, OutputMode::Compact).render()
    }

    /// Full forensic view
    pub fn forensic(doc: &SurfaceDocument) -> String {
        OperatorEngine::transform(doc, OutputMode::Full).render()
    }

    /// Narrative view
    pub fn narrative(doc: &SurfaceDocument) -> String {
        OperatorEngine::transform(doc, OutputMode::Narrative).render()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> SurfaceDocument {
        SurfaceDocument {
            meta: SurfaceMeta { surface_type: SurfaceType::Agent, view: SurfaceView::Ops, generated_at: 0 },
            header: SurfaceHeader {
                title: "Test Agent".into(),
                subject: SubjectIdentity::new(ResourceKind::Agent, "test-001"),
                state: StateVector::active_verified(),
                badges: vec![SurfaceBadge { label: "Status".into(), value: "FAILED".into(), severity: Severity::Critical }],
                time_range: None,
            },
            summary: Some("Test summary".into()),
            sections: vec![
                SurfaceSection {
                    title: "Findings".into(),
                    kind: SectionKind::Findings,
                    content: SectionContent::Findings(vec![
                        Finding { code: "ERR-001".into(), message: "Pipeline stage failed".into(), severity: Severity::Critical, link: None },
                    ]),
                    collapsed: false,
                },
            ],
            actions: vec![
                SurfaceAction { label: "Retry".into(), command: "connectorctl retry test-001".into(), description: "Retry failed pipeline".into(), primary: true },
            ],
            footer: None,
        }
    }

    #[test]
    fn test_operator_output_compact() {
        let doc = sample_doc();
        let output = OperatorEngine::transform(&doc, OutputMode::Compact);
        let rendered = output.render();
        assert!(rendered.contains("CRITICAL"));
        assert!(rendered.contains("ACTION"));
    }

    #[test]
    fn test_operator_output_summary() {
        let doc = sample_doc();
        let output = OperatorEngine::transform(&doc, OutputMode::Summary);
        let rendered = output.render();
        assert!(rendered.contains("DRILL DOWN"));
    }

    #[test]
    fn test_quick_status() {
        let doc = sample_doc();
        let status = QuickStatus::from_surface(&doc);
        assert_eq!(status.level, StatusLevel::Critical);
        assert!(status.render().contains("✖"));
    }

    #[test]
    fn test_view_compressor() {
        let doc = sample_doc();
        let compact = ViewCompressor::compact(&doc);
        let summary = ViewCompressor::summary(&doc);
        assert!(compact.len() < summary.len());
    }
}
