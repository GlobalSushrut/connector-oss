//! Export Formats — JSON, Markdown, HTML, PDF stub
//!
//! Enterprise-grade export for compliance, reporting, and integration.

use super::document::*;
use super::renderer::Renderer;
use serde::{Deserialize, Serialize};

/// Export format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Markdown,
    Html,
    Pdf,
    Csv,
    Yaml,
}

impl ExportFormat {
    pub fn extension(&self) -> &'static str {
        match self { Self::Json => "json", Self::Markdown => "md", Self::Html => "html", Self::Pdf => "pdf", Self::Csv => "csv", Self::Yaml => "yaml" }
    }

    pub fn mime_type(&self) -> &'static str {
        match self { Self::Json => "application/json", Self::Markdown => "text/markdown", Self::Html => "text/html", Self::Pdf => "application/pdf", Self::Csv => "text/csv", Self::Yaml => "application/yaml" }
    }
}

/// Markdown renderer
pub struct MarkdownRenderer;

impl Renderer for MarkdownRenderer {
    fn render(&self, doc: &SurfaceDocument) -> String {
        let mut out = String::new();
        
        // Title
        out.push_str(&format!("# {}\n\n", doc.header.title));
        
        // State badges
        out.push_str(&format!("**State:** {}\n\n", doc.header.state.display()));
        
        // Badges
        if !doc.header.badges.is_empty() {
            for badge in &doc.header.badges {
                out.push_str(&format!("- **{}:** {}\n", badge.label, badge.value));
            }
            out.push('\n');
        }
        
        // Summary
        if let Some(ref summary) = doc.summary {
            out.push_str(&format!("> {}\n\n", summary));
        }
        
        // Sections
        for section in &doc.sections {
            out.push_str(&format!("## {}\n\n", section.title));
            out.push_str(&self.render_content(&section.content));
            out.push('\n');
        }
        
        // Actions
        if !doc.actions.is_empty() {
            out.push_str("## Actions\n\n");
            for action in &doc.actions {
                out.push_str(&format!("- **{}**: {} `{}`\n", action.label, action.description, action.command));
            }
            out.push('\n');
        }
        
        // Footer
        if let Some(ref footer) = doc.footer {
            out.push_str("---\n\n");
            out.push_str(&format!("*Generated: {} | Receipts: {} | Chain: {}*\n",
                footer.timestamp, footer.receipt_count, if footer.chain_valid { "valid" } else { "invalid" }));
        }
        
        out
    }
}

impl MarkdownRenderer {
    fn render_content(&self, content: &SectionContent) -> String {
        match content {
            SectionContent::Stats(items) => {
                let mut out = String::new();
                for item in items {
                    out.push_str(&format!("| {} | {} |\n", item.label, item.value));
                }
                out
            },
            SectionContent::KeyValue(items) => {
                let mut out = "| Key | Value |\n|-----|-------|\n".to_string();
                for item in items {
                    out.push_str(&format!("| {} | {} |\n", item.key, item.value));
                }
                out
            },
            SectionContent::Timeline(events) => {
                let mut out = String::new();
                for event in events {
                    out.push_str(&format!("- `{}` **{}** {}\n", event.timestamp, event.event_type, event.message));
                }
                out
            },
            SectionContent::Findings(findings) => {
                let mut out = String::new();
                for f in findings {
                    let icon = f.severity.icon();
                    out.push_str(&format!("- {} **{}** {}\n", icon, f.code, f.message));
                }
                out
            },
            SectionContent::Evidence(items) => {
                let mut out = String::new();
                for item in items {
                    let icon = if item.verified { "✓" } else { "?" };
                    out.push_str(&format!("- {} {} `{}`\n", icon, item.evidence_type, item.cid));
                }
                out
            },
            SectionContent::Trace(spans) => {
                let mut out = String::new();
                for span in spans {
                    let indent = "  ".repeat(span.depth as usize);
                    out.push_str(&format!("{}• {} ({}ms)\n", indent, span.name, span.duration_ms));
                }
                out
            },
            SectionContent::Narrative(text) => format!("{}\n", text),
            SectionContent::RawData(blob) => format!("```\n{}\n```\n", blob.preview),
            SectionContent::Links(links) => {
                let mut out = String::new();
                for link in links {
                    out.push_str(&format!("- [{}]({})\n", link.label, link.command));
                }
                out
            },
            SectionContent::List(items) => {
                let mut out = String::new();
                for item in items {
                    out.push_str(&format!("- {}\n", item.text));
                }
                out
            },
        }
    }
}

/// HTML renderer
pub struct HtmlRenderer {
    pub include_styles: bool,
}

impl Default for HtmlRenderer {
    fn default() -> Self { Self { include_styles: true } }
}

impl Renderer for HtmlRenderer {
    fn render(&self, doc: &SurfaceDocument) -> String {
        let mut out = String::new();
        
        if self.include_styles {
            out.push_str(r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>"#);
            out.push_str(&doc.header.title);
            out.push_str(r#"</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
.surface { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 24px; }
.header { border-bottom: 1px solid #eee; padding-bottom: 16px; margin-bottom: 16px; }
.title { font-size: 24px; font-weight: 600; margin: 0; }
.state { color: #666; font-size: 14px; margin-top: 8px; }
.badges { display: flex; gap: 8px; margin-top: 12px; }
.badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; }
.badge-ok { background: #d4edda; color: #155724; }
.badge-warn { background: #fff3cd; color: #856404; }
.badge-risk { background: #f8d7da; color: #721c24; }
.summary { background: #f8f9fa; padding: 12px; border-radius: 4px; margin-bottom: 16px; }
.section { margin-bottom: 24px; }
.section-title { font-size: 16px; font-weight: 600; margin-bottom: 12px; border-bottom: 1px solid #eee; padding-bottom: 8px; }
.timeline-item { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid #f0f0f0; }
.timeline-time { color: #666; font-family: monospace; }
.finding { display: flex; align-items: center; gap: 8px; padding: 8px 0; }
.finding-ok { color: #28a745; }
.finding-warn { color: #ffc107; }
.finding-critical { color: #dc3545; }
.actions { margin-top: 24px; padding-top: 16px; border-top: 1px solid #eee; }
.action { display: inline-block; padding: 8px 16px; background: #007bff; color: white; border-radius: 4px; text-decoration: none; margin-right: 8px; }
.action:hover { background: #0056b3; }
.footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #eee; color: #666; font-size: 12px; }
</style>
</head><body>
<div class="surface">
"#);
        }
        
        // Header
        out.push_str(&format!(r#"<div class="header">
<h1 class="title">{}</h1>
<div class="state">{}</div>
<div class="badges">"#, doc.header.title, doc.header.state.display()));
        
        for badge in &doc.header.badges {
            let class = match badge.severity { Severity::Ok => "badge-ok", Severity::Warn => "badge-warn", _ => "badge-risk" };
            out.push_str(&format!(r#"<span class="badge {}">{}: {}</span>"#, class, badge.label, badge.value));
        }
        out.push_str("</div></div>\n");
        
        // Summary
        if let Some(ref summary) = doc.summary {
            out.push_str(&format!(r#"<div class="summary">{}</div>"#, summary));
        }
        
        // Sections
        for section in &doc.sections {
            out.push_str(&format!(r#"<div class="section"><div class="section-title">{}</div>"#, section.title));
            out.push_str(&self.render_content_html(&section.content));
            out.push_str("</div>\n");
        }
        
        // Actions
        if !doc.actions.is_empty() {
            out.push_str(r#"<div class="actions">"#);
            for action in &doc.actions {
                out.push_str(&format!("<a class=\"action\" href=\"#\" title=\"{}\">{}</a>", action.command, action.label));
            }
            out.push_str("</div>\n");
        }
        
        // Footer
        if let Some(ref footer) = doc.footer {
            out.push_str(&format!(r#"<div class="footer">Generated: {} | Receipts: {} | Chain: {}</div>"#,
                footer.timestamp, footer.receipt_count, if footer.chain_valid { "valid" } else { "invalid" }));
        }
        
        if self.include_styles {
            out.push_str("</div></body></html>");
        }
        
        out
    }
}

impl HtmlRenderer {
    fn render_content_html(&self, content: &SectionContent) -> String {
        match content {
            SectionContent::Timeline(events) => {
                let mut out = String::new();
                for event in events {
                    out.push_str(&format!(r#"<div class="timeline-item"><span class="timeline-time">{}</span><strong>{}</strong><span>{}</span></div>"#,
                        event.timestamp, event.event_type, event.message));
                }
                out
            },
            SectionContent::Findings(findings) => {
                let mut out = String::new();
                for f in findings {
                    let class = match f.severity { Severity::Ok => "finding-ok", Severity::Warn => "finding-warn", _ => "finding-critical" };
                    out.push_str(&format!(r#"<div class="finding {}"><span>{}</span><strong>{}</strong><span>{}</span></div>"#,
                        class, f.severity.icon(), f.code, f.message));
                }
                out
            },
            SectionContent::Narrative(text) => format!("<p>{}</p>", text),
            _ => "<p>[Content]</p>".into(),
        }
    }
}

/// Exporter for generating files
pub struct Exporter;

impl Exporter {
    pub fn export(doc: &SurfaceDocument, format: ExportFormat) -> String {
        match format {
            ExportFormat::Json => super::renderer::JsonRenderer.render(doc),
            ExportFormat::Markdown => MarkdownRenderer.render(doc),
            ExportFormat::Html => HtmlRenderer::default().render(doc),
            ExportFormat::Yaml => serde_yaml::to_string(doc).unwrap_or_default(),
            ExportFormat::Csv => Self::to_csv(doc),
            ExportFormat::Pdf => "[PDF export requires external library]".into(),
        }
    }

    fn to_csv(doc: &SurfaceDocument) -> String {
        let mut out = "section,type,key,value\n".to_string();
        for section in &doc.sections {
            match &section.content {
                SectionContent::Stats(items) => {
                    for item in items {
                        out.push_str(&format!("\"{}\",stat,\"{}\",\"{}\"\n", section.title, item.label, item.value));
                    }
                },
                SectionContent::KeyValue(items) => {
                    for item in items {
                        out.push_str(&format!("\"{}\",kv,\"{}\",\"{}\"\n", section.title, item.key, item.value));
                    }
                },
                _ => {},
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::builder::SurfaceBuilder;

    #[test]
    fn test_markdown_export() {
        let doc = SurfaceBuilder::agent("test").judgment_ok("OK").stats("Health", vec![("CPU", "12%")]).build();
        let md = Exporter::export(&doc, ExportFormat::Markdown);
        assert!(md.contains("# AGENT:"));
        assert!(md.contains("CPU"));
    }

    #[test]
    fn test_html_export() {
        let doc = SurfaceBuilder::agent("test").judgment_ok("OK").build();
        let html = Exporter::export(&doc, ExportFormat::Html);
        assert!(html.contains("<!DOCTYPE html>"));
    }
}
