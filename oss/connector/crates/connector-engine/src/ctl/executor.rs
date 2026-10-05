//! Command Executor — Time-Aware Query Engine

use super::grammar::{Command, Verb, Noun};
use super::time::{TimeSelector, ResolvedTimeRange};
use super::identity::ResourceIdentity;
use super::output::OutputMode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub command: String,
    pub success: bool,
    pub surface: SurfaceDocument,
    pub duration_ms: u64,
    pub time_context: TimeContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeContext {
    pub selector: TimeSelector,
    pub resolved: ResolvedTimeRange,
    pub is_time_travel: bool,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceDocument {
    pub title: String,
    pub doc_type: SurfaceType,
    pub header: SurfaceHeader,
    pub summary: Option<String>,
    pub sections: Vec<SurfaceSection>,
    pub actions: Vec<SurfaceAction>,
    pub footer: Option<SurfaceFooter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceType { Debug, Audit, Compliance, Explain, Trace, Inspect, Review }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceHeader {
    pub subject: String,
    pub identity: ResourceIdentity,
    pub state: SurfaceState,
    pub badges: Vec<SurfaceBadge>,
    pub time_range: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceState { Stable, Active, Verified, Degraded, Blocked, Partial, Unverified, Failed }

impl SurfaceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable", Self::Active => "active", Self::Verified => "verified",
            Self::Degraded => "degraded", Self::Blocked => "blocked", Self::Partial => "partial",
            Self::Unverified => "unverified", Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceBadge { pub label: String, pub value: String, pub severity: Severity }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity { Ok, Info, Warn, Risk, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceSection {
    pub title: String,
    pub kind: SectionKind,
    pub content: SectionContent,
    pub collapsed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionKind { StatsGrid, KeyValueTable, Timeline, Findings, List, Evidence, Narrative, Trace, RawData, Links }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectionContent {
    Stats(Vec<StatItem>),
    KeyValue(Vec<KeyValueItem>),
    Timeline(Vec<TimelineEvent>),
    Findings(Vec<Finding>),
    List(Vec<ListItem>),
    Evidence(Vec<EvidenceItem>),
    Narrative(String),
    Trace(Vec<TraceSpan>),
    RawData(RawDataBlob),
    Links(Vec<DeepLink>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatItem { pub label: String, pub value: String, pub link: Option<DeepLink> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValueItem { pub key: String, pub value: String, pub link: Option<DeepLink>, pub raw: Option<RawDataBlob> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent { pub timestamp: String, pub event_type: String, pub message: String, pub severity: Severity, pub link: Option<DeepLink> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding { pub severity: Severity, pub code: String, pub message: String, pub link: Option<DeepLink> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListItem { pub text: String, pub link: Option<DeepLink> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem { pub evidence_type: String, pub cid: String, pub verified: bool, pub link: DeepLink }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan { pub span_id: String, pub name: String, pub duration_ms: u64, pub status: String, pub depth: u32, pub link: Option<DeepLink> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepLink {
    pub label: String,
    pub action: LinkAction,
    pub command: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkAction { Inspect, Cat, Verify, Trace, Expand, Navigate, Export }

impl DeepLink {
    pub fn inspect(target: &str) -> Self {
        Self { label: "[inspect]".into(), action: LinkAction::Inspect, command: format!("connectorctl inspect {}", target), url: Some(format!("/ui/{}", target)) }
    }
    pub fn cat(target: &str) -> Self {
        Self { label: "[cat]".into(), action: LinkAction::Cat, command: format!("connectorctl show {}", target), url: Some(format!("/ui/{}/raw", target)) }
    }
    pub fn verify(target: &str) -> Self {
        Self { label: "[verify]".into(), action: LinkAction::Verify, command: format!("connectorctl verify {}", target), url: Some(format!("/ui/{}/verify", target)) }
    }
    pub fn trace(target: &str) -> Self {
        Self { label: "[trace]".into(), action: LinkAction::Trace, command: format!("connectorctl trace {}", target), url: Some(format!("/ui/{}/trace", target)) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDataBlob {
    pub id: String,
    pub content_type: ContentType,
    pub size: usize,
    pub preview: String,
    pub content: BlobContent,
    pub expanded: bool,
    pub fetch_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType { Json, Text, Binary, Markdown, Yaml, Code }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlobContent { Inline(String), External { url: String }, Pending }

impl RawDataBlob {
    pub fn json(id: &str, content: &serde_json::Value) -> Self {
        let full = serde_json::to_string_pretty(content).unwrap_or_default();
        let preview = if full.len() > 80 { format!("{}...", &full[..80]) } else { full.clone() };
        Self { id: id.into(), content_type: ContentType::Json, size: full.len(), preview, content: BlobContent::Inline(full), expanded: false, fetch_command: format!("connectorctl show {} --raw", id) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceAction { pub label: String, pub description: String, pub command: String, pub primary: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceFooter { pub root_hash: Option<String>, pub verified: bool, pub receipt_count: u32, pub chain_valid: bool, pub timestamp: String }

pub struct CommandExecutor { now_ms: i64 }

impl Default for CommandExecutor {
    fn default() -> Self { Self::new() }
}

impl CommandExecutor {
    pub fn new() -> Self {
        Self { now_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64 }
    }

    pub fn execute(&self, cmd: &Command) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = cmd.time.resolve(self.now_ms);
        let time_context = TimeContext { selector: cmd.time.clone(), resolved, is_time_travel: cmd.is_time_travel(), now_ms: self.now_ms };
        let surface = self.build_surface(cmd, &time_context);
        ExecutionResult { command: cmd.to_cli_string(), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context }
    }

    fn build_surface(&self, cmd: &Command, ctx: &TimeContext) -> SurfaceDocument {
        let target = cmd.target.as_ref().map(|t| t.canonical()).unwrap_or_else(|| cmd.noun.as_str().to_string());
        match cmd.verb {
            Verb::Trace => super::surfaces::build_trace_surface(&target, ctx),
            Verb::Inspect => super::surfaces::build_inspect_surface(&target, ctx),
            Verb::Review => super::surfaces::build_review_surface(&target, ctx),
            Verb::Explain => super::surfaces::build_explain_surface(&target, ctx),
            _ => super::surfaces::build_debug_surface(&target, ctx),
        }
    }

    pub fn execute_debug(&self, target: &str, time: &TimeSelector) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = time.resolve(self.now_ms);
        let ctx = TimeContext { selector: time.clone(), resolved, is_time_travel: !matches!(time, TimeSelector::Now), now_ms: self.now_ms };
        let surface = super::surfaces::build_debug_surface(target, &ctx);
        ExecutionResult { command: format!("connectorctl debug {}", target), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context: ctx }
    }

    pub fn execute_audit(&self, target: &str, time: &TimeSelector) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = time.resolve(self.now_ms);
        let ctx = TimeContext { selector: time.clone(), resolved, is_time_travel: !matches!(time, TimeSelector::Now), now_ms: self.now_ms };
        let surface = super::surfaces::build_audit_surface(target, &ctx);
        ExecutionResult { command: format!("connectorctl audit {}", target), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context: ctx }
    }

    pub fn execute_compliance(&self, target: &str, time: &TimeSelector) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = time.resolve(self.now_ms);
        let ctx = TimeContext { selector: time.clone(), resolved, is_time_travel: !matches!(time, TimeSelector::Now), now_ms: self.now_ms };
        let surface = super::surfaces::build_compliance_surface(target, &ctx);
        ExecutionResult { command: format!("connectorctl compliance {}", target), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context: ctx }
    }

    pub fn execute_explain(&self, target: &str, time: &TimeSelector) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = time.resolve(self.now_ms);
        let ctx = TimeContext { selector: time.clone(), resolved, is_time_travel: !matches!(time, TimeSelector::Now), now_ms: self.now_ms };
        let surface = super::surfaces::build_explain_surface(target, &ctx);
        ExecutionResult { command: format!("connectorctl explain {}", target), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context: ctx }
    }

    pub fn execute_trace(&self, target: &str, time: &TimeSelector) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = time.resolve(self.now_ms);
        let ctx = TimeContext { selector: time.clone(), resolved, is_time_travel: !matches!(time, TimeSelector::Now), now_ms: self.now_ms };
        let surface = super::surfaces::build_trace_surface(target, &ctx);
        ExecutionResult { command: format!("connectorctl trace {}", target), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context: ctx }
    }

    pub fn execute_inspect(&self, target: &str, time: &TimeSelector) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = time.resolve(self.now_ms);
        let ctx = TimeContext { selector: time.clone(), resolved, is_time_travel: !matches!(time, TimeSelector::Now), now_ms: self.now_ms };
        let surface = super::surfaces::build_inspect_surface(target, &ctx);
        ExecutionResult { command: format!("connectorctl inspect {}", target), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context: ctx }
    }

    pub fn execute_review(&self, target: &str, time: &TimeSelector) -> ExecutionResult {
        let start = std::time::Instant::now();
        let resolved = time.resolve(self.now_ms);
        let ctx = TimeContext { selector: time.clone(), resolved, is_time_travel: !matches!(time, TimeSelector::Now), now_ms: self.now_ms };
        let surface = super::surfaces::build_review_surface(target, &ctx);
        ExecutionResult { command: format!("connectorctl review {}", target), success: true, surface, duration_ms: start.elapsed().as_millis() as u64, time_context: ctx }
    }
}
