//! Trace — structured, multi-audience observability for the dual kernel.
//!
//! Converts raw `KernelAuditEntry` logs into a nested span tree that is:
//! - **Human-readable**: narrative labels, emoji status, box-drawing timeline
//! - **LLM-readable**: structured natural language summaries per step
//! - **Tool-compatible**: OTel GenAI semantic convention attributes
//! - **Raw-preserving**: full kernel data always accessible

use serde::{Deserialize, Serialize};
use vac_core::kernel::MemoryKernel;
use vac_core::types::{KernelAuditEntry, MemoryKernelOp, OpOutcome};

// ─── Span Types ──────────────────────────────────────────────────

/// Span type — aligned with OTel GenAI + Langfuse + OpenAI Agents SDK.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpanType {
    /// Agent invocation (OTel: invoke_agent)
    Agent,
    /// LLM model call (OTel: chat / generate_content)
    Generation,
    /// Tool/function call (OTel: execute_tool)
    ToolCall,
    /// Memory write operation
    MemoryWrite,
    /// Memory read operation
    MemoryRead,
    /// Output guardrail check
    Guardrail,
    /// AAPI authorization check
    Authorization,
    /// Actor-to-actor handoff
    Handoff,
    /// Security verification (CID, Merkle, signing)
    Security,
    /// Agent lifecycle (register, start, terminate)
    Lifecycle,
    /// Session management
    Session,
    /// Access control (grant, revoke)
    Access,
    /// Maintenance (GC, integrity check)
    Maintenance,
}

/// Span severity level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpanLevel {
    Debug,
    Info,
    Warning,
    Error,
}

/// Span completion status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    Ok,
    Error,
    Denied,
    Pending,
    Skipped,
}

impl From<&OpOutcome> for SpanStatus {
    fn from(outcome: &OpOutcome) -> Self {
        match outcome {
            OpOutcome::Success => SpanStatus::Ok,
            OpOutcome::Failed => SpanStatus::Error,
            OpOutcome::Denied => SpanStatus::Denied,
            OpOutcome::Pending => SpanStatus::Pending,
            OpOutcome::Skipped => SpanStatus::Skipped,
        }
    }
}

// ─── Span ────────────────────────────────────────────────────────

/// A single span in the trace tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    // Identity (OTel-compatible)
    pub span_id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,

    // Classification
    pub span_type: SpanType,
    pub name: String,
    pub level: SpanLevel,

    // Timing
    pub started_at: String,
    pub ended_at: Option<String>,
    pub duration_ms: u64,

    // Content
    pub input: Option<String>,
    pub output: Option<String>,
    pub status: SpanStatus,
    pub status_emoji: String,

    // AI-specific (OTel GenAI semconv)
    pub agent_name: Option<String>,
    pub agent_id: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub tokens_in: Option<u64>,
    pub tokens_out: Option<u64>,
    pub cost_usd: Option<f64>,

    // Connector-specific (visible, labeled)
    pub cid: Option<String>,
    pub cid_label: Option<String>,
    pub trust_score: Option<u32>,
    pub authorization: Option<String>,
    pub compliance: Vec<String>,
    pub merkle_root: Option<String>,
    pub audit_id: Option<String>,

    // Nesting
    pub children: Vec<Span>,
}

// ─── Trace ───────────────────────────────────────────────────────

/// A complete trace — one pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub trace_id: String,
    pub session_id: Option<String>,
    pub pipeline_name: String,
    pub started_at: String,
    pub ended_at: String,
    pub duration_ms: u64,
    pub status: SpanStatus,
    pub summary: TraceSummary,
    pub spans: Vec<Span>,
}

/// Trace summary — the human-friendly dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    /// Natural language narrative of what happened
    pub narrative: String,
    /// Per-actor step summaries
    pub steps: Vec<StepSummary>,

    // Counts
    pub actors: usize,
    pub total_spans: usize,
    pub llm_calls: usize,
    pub tool_calls: usize,
    pub memory_ops: usize,

    // Cost
    pub total_tokens: u64,
    pub total_cost_usd: f64,

    // Trust (with explanation)
    pub trust_score: u32,
    pub trust_grade: String,
    pub trust_explanation: String,

    // Security
    pub authorization_summary: String,
    pub compliance: Vec<String>,
}

/// Per-actor step summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepSummary {
    pub step: usize,
    pub agent: String,
    pub action: String,
    pub tools_used: Vec<String>,
    pub authorization: String,
    pub memories_used: usize,
    pub duration_ms: u64,
}

// ─── Kernel → Human Translation ──────────────────────────────────

/// Translate a kernel operation to a human-readable label.
pub fn op_to_human(op: &MemoryKernelOp) -> &'static str {
    match op {
        MemoryKernelOp::AgentRegister => "Registered agent",
        MemoryKernelOp::AgentStart => "Started agent",
        MemoryKernelOp::AgentSuspend => "Suspended agent",
        MemoryKernelOp::AgentResume => "Resumed agent",
        MemoryKernelOp::AgentTerminate => "Terminated agent",
        MemoryKernelOp::MemAlloc => "Allocated memory",
        MemoryKernelOp::MemWrite => "Stored memory",
        MemoryKernelOp::MemRead => "Recalled memory",
        MemoryKernelOp::MemEvict => "Archived memory",
        MemoryKernelOp::MemPromote => "Promoted memory tier",
        MemoryKernelOp::MemDemote => "Demoted memory tier",
        MemoryKernelOp::MemClear => "Cleared memory",
        MemoryKernelOp::MemSeal => "Sealed memory (immutable)",
        MemoryKernelOp::SessionCreate => "Started session",
        MemoryKernelOp::SessionClose => "Ended session",
        MemoryKernelOp::SessionCompress => "Compressed session",
        MemoryKernelOp::ContextSnapshot => "Saved context snapshot",
        MemoryKernelOp::ContextRestore => "Restored context",
        MemoryKernelOp::AccessGrant => "Granted access",
        MemoryKernelOp::AccessRevoke => "Revoked access",
        MemoryKernelOp::AccessCheck => "Checked access",
        MemoryKernelOp::GarbageCollect => "Cleaned up",
        MemoryKernelOp::IndexRebuild => "Rebuilt index",
        MemoryKernelOp::IntegrityCheck => "Verified integrity",
        MemoryKernelOp::ToolDispatch => "Called tool",
        MemoryKernelOp::PortCreate => "Created port",
        MemoryKernelOp::PortBind => "Bound port",
        MemoryKernelOp::PortSend => "Sent message",
        MemoryKernelOp::PortReceive => "Received message",
        MemoryKernelOp::PortClose => "Closed port",
        MemoryKernelOp::PortDelegate => "Delegated via port",
    }
}

/// Translate a kernel operation to an LLM-friendly label.
pub fn op_to_llm(op: &MemoryKernelOp) -> &'static str {
    match op {
        MemoryKernelOp::AgentRegister => "agent_registered",
        MemoryKernelOp::AgentStart => "agent_started",
        MemoryKernelOp::AgentSuspend => "agent_suspended",
        MemoryKernelOp::AgentResume => "agent_resumed",
        MemoryKernelOp::AgentTerminate => "agent_terminated",
        MemoryKernelOp::MemAlloc => "memory_allocated",
        MemoryKernelOp::MemWrite => "memory_stored",
        MemoryKernelOp::MemRead => "memory_recalled",
        MemoryKernelOp::MemEvict => "memory_archived",
        MemoryKernelOp::MemPromote => "memory_promoted",
        MemoryKernelOp::MemDemote => "memory_demoted",
        MemoryKernelOp::MemClear => "memory_cleared",
        MemoryKernelOp::MemSeal => "memory_sealed",
        MemoryKernelOp::SessionCreate => "session_started",
        MemoryKernelOp::SessionClose => "session_ended",
        MemoryKernelOp::SessionCompress => "session_compressed",
        MemoryKernelOp::ContextSnapshot => "context_saved",
        MemoryKernelOp::ContextRestore => "context_restored",
        MemoryKernelOp::AccessGrant => "access_granted",
        MemoryKernelOp::AccessRevoke => "access_revoked",
        MemoryKernelOp::AccessCheck => "access_checked",
        MemoryKernelOp::GarbageCollect => "cleanup",
        MemoryKernelOp::IndexRebuild => "index_rebuilt",
        MemoryKernelOp::IntegrityCheck => "integrity_verified",
        MemoryKernelOp::ToolDispatch => "tool_called",
        MemoryKernelOp::PortCreate => "port_created",
        MemoryKernelOp::PortBind => "port_bound",
        MemoryKernelOp::PortSend => "message_sent",
        MemoryKernelOp::PortReceive => "message_received",
        MemoryKernelOp::PortClose => "port_closed",
        MemoryKernelOp::PortDelegate => "port_delegated",
    }
}

/// Translate outcome to emoji.
pub fn outcome_emoji(outcome: &OpOutcome) -> &'static str {
    match outcome {
        OpOutcome::Success => "✅",
        OpOutcome::Denied => "❌",
        OpOutcome::Failed => "💥",
        OpOutcome::Skipped => "⏭️",
        OpOutcome::Pending => "⏳",
    }
}

/// Classify a kernel op into a SpanType.
pub fn op_to_span_type(op: &MemoryKernelOp) -> SpanType {
    match op {
        MemoryKernelOp::AgentRegister | MemoryKernelOp::AgentStart |
        MemoryKernelOp::AgentSuspend | MemoryKernelOp::AgentResume |
        MemoryKernelOp::AgentTerminate => SpanType::Lifecycle,

        MemoryKernelOp::MemWrite | MemoryKernelOp::MemAlloc |
        MemoryKernelOp::MemEvict | MemoryKernelOp::MemPromote |
        MemoryKernelOp::MemDemote | MemoryKernelOp::MemClear |
        MemoryKernelOp::MemSeal => SpanType::MemoryWrite,

        MemoryKernelOp::MemRead => SpanType::MemoryRead,

        MemoryKernelOp::SessionCreate | MemoryKernelOp::SessionClose |
        MemoryKernelOp::SessionCompress => SpanType::Session,

        MemoryKernelOp::ContextSnapshot | MemoryKernelOp::ContextRestore => SpanType::Security,

        MemoryKernelOp::AccessGrant | MemoryKernelOp::AccessRevoke |
        MemoryKernelOp::AccessCheck => SpanType::Access,

        MemoryKernelOp::ToolDispatch => SpanType::ToolCall,

        MemoryKernelOp::GarbageCollect | MemoryKernelOp::IndexRebuild |
        MemoryKernelOp::IntegrityCheck => SpanType::Maintenance,

        MemoryKernelOp::PortCreate | MemoryKernelOp::PortBind |
        MemoryKernelOp::PortSend | MemoryKernelOp::PortReceive |
        MemoryKernelOp::PortClose | MemoryKernelOp::PortDelegate => SpanType::Handoff,
    }
}

/// Determine span level from outcome.
pub fn outcome_to_level(outcome: &OpOutcome) -> SpanLevel {
    match outcome {
        OpOutcome::Success => SpanLevel::Info,
        OpOutcome::Denied => SpanLevel::Warning,
        OpOutcome::Failed => SpanLevel::Error,
        OpOutcome::Skipped => SpanLevel::Debug,
        OpOutcome::Pending => SpanLevel::Warning,
    }
}

// ─── OTel GenAI operation name ───────────────────────────────────

/// Map kernel op to OTel GenAI `gen_ai.operation.name`.
pub fn op_to_otel_name(op: &MemoryKernelOp) -> &'static str {
    match op {
        MemoryKernelOp::AgentRegister => "create_agent",
        MemoryKernelOp::AgentStart => "invoke_agent",
        MemoryKernelOp::ToolDispatch => "execute_tool",
        MemoryKernelOp::MemWrite => "memory.write",
        MemoryKernelOp::MemRead => "memory.read",
        MemoryKernelOp::AccessGrant | MemoryKernelOp::AccessRevoke |
        MemoryKernelOp::AccessCheck => "authorize",
        MemoryKernelOp::IntegrityCheck => "security.verify",
        MemoryKernelOp::PortCreate | MemoryKernelOp::PortBind |
        MemoryKernelOp::PortSend | MemoryKernelOp::PortReceive |
        MemoryKernelOp::PortClose | MemoryKernelOp::PortDelegate => "messaging",
        _ => "internal",
    }
}

// ─── TraceBuilder ────────────────────────────────────────────────

/// Builds a Trace from kernel state.
pub struct TraceBuilder;

impl TraceBuilder {
    /// Convert kernel audit log into a structured Trace.
    pub fn from_kernel(
        kernel: &MemoryKernel,
        pipeline_name: &str,
        trace_id: &str,
        actor_names: &[String],
        compliance: &[String],
        duration_ms: u64,
        trust_score: u32,
        trust_grade: &str,
        trust_dims: &crate::trust::TrustDimensions,
    ) -> Trace {
        let audit_log = kernel.audit_log();
        let now = chrono::Utc::now().to_rfc3339();

        // Build spans from audit entries
        let spans: Vec<Span> = audit_log.iter().enumerate().map(|(i, entry)| {
            Self::entry_to_span(entry, trace_id, i)
        }).collect();

        // Count span types
        let llm_calls = 0; // Would come from actual LLM calls in production
        let tool_calls = spans.iter().filter(|s| s.span_type == SpanType::ToolCall).count();
        let memory_ops = spans.iter().filter(|s| s.span_type == SpanType::MemoryWrite || s.span_type == SpanType::MemoryRead).count();

        // Authorization counts
        let authorized = audit_log.iter().filter(|e| e.outcome == OpOutcome::Success).count();
        let denied = audit_log.iter().filter(|e| e.outcome == OpOutcome::Denied).count();
        let pending = audit_log.iter().filter(|e| e.outcome == OpOutcome::Pending || e.outcome == OpOutcome::Skipped).count();

        let auth_summary = format!("{} authorized, {} denied, {} pending", authorized, denied, pending);

        // Build trust explanation
        let trust_explanation = format!(
            "{}/20 memory integrity, {}/20 audit completeness, {}/20 authorization coverage, {}/20 decision provenance, {}/20 operational health",
            trust_dims.memory_integrity,
            trust_dims.audit_completeness,
            trust_dims.authorization_coverage,
            trust_dims.decision_provenance,
            trust_dims.operational_health,
        );

        // Build narrative
        let narrative = if actor_names.is_empty() {
            format!("Pipeline '{}' completed in {}ms with trust {}/100 ({})", pipeline_name, duration_ms, trust_score, trust_grade)
        } else {
            let actor_list = actor_names.join(" → ");
            format!("{} ran in {}ms. Trust: {}/100 ({}). {}", actor_list, duration_ms, trust_score, trust_grade, auth_summary)
        };

        // Build per-actor step summaries
        let steps: Vec<StepSummary> = actor_names.iter().enumerate().map(|(i, name)| {
            StepSummary {
                step: i + 1,
                agent: name.clone(),
                action: format!("Agent '{}' processed input", name),
                tools_used: Vec::new(),
                authorization: "all allowed".to_string(),
                memories_used: 0,
                duration_ms: duration_ms / actor_names.len().max(1) as u64,
            }
        }).collect();

        let status = if denied > 0 { SpanStatus::Denied } else { SpanStatus::Ok };

        Trace {
            trace_id: trace_id.to_string(),
            session_id: None,
            pipeline_name: pipeline_name.to_string(),
            started_at: now.clone(),
            ended_at: now,
            duration_ms,
            status,
            summary: TraceSummary {
                narrative,
                steps,
                actors: actor_names.len(),
                total_spans: spans.len(),
                llm_calls,
                tool_calls,
                memory_ops,
                total_tokens: 0,
                total_cost_usd: 0.0,
                trust_score,
                trust_grade: trust_grade.to_string(),
                trust_explanation,
                authorization_summary: auth_summary,
                compliance: compliance.to_vec(),
            },
            spans,
        }
    }

    /// Convert a single KernelAuditEntry into a Span.
    fn entry_to_span(entry: &KernelAuditEntry, trace_id: &str, index: usize) -> Span {
        let span_type = op_to_span_type(&entry.operation);
        let human_label = op_to_human(&entry.operation);
        let emoji = outcome_emoji(&entry.outcome);
        let level = outcome_to_level(&entry.outcome);
        let status = SpanStatus::from(&entry.outcome);

        let name = if let Some(target) = &entry.target {
            // Truncate long CIDs for readability
            let short_target = if target.len() > 20 {
                format!("{}...{}", &target[..8], &target[target.len()-4..])
            } else {
                target.clone()
            };
            format!("{}: {}", human_label, short_target)
        } else {
            human_label.to_string()
        };

        let started_at = chrono::DateTime::from_timestamp_millis(entry.timestamp)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| entry.timestamp.to_string());

        let cid_label = match &entry.target {
            Some(t) if t.starts_with("bafy") => Some("memory".to_string()),
            Some(t) if t.starts_with("ns:") => Some("namespace".to_string()),
            Some(t) if t.starts_with("sess:") => Some("session".to_string()),
            Some(t) if t.starts_with("pid:") => Some("agent".to_string()),
            _ => None,
        };

        Span {
            span_id: format!("span_{:04}", index),
            trace_id: trace_id.to_string(),
            parent_span_id: None,
            span_type,
            name,
            level,
            started_at,
            ended_at: None,
            duration_ms: entry.duration_us.unwrap_or(0) / 1000,
            input: entry.reason.clone(),
            output: entry.error.clone(),
            status,
            status_emoji: emoji.to_string(),
            agent_name: None,
            agent_id: Some(entry.agent_pid.clone()),
            model: None,
            provider: None,
            tokens_in: None,
            tokens_out: None,
            cost_usd: None,
            cid: entry.target.clone(),
            cid_label,
            trust_score: None,
            authorization: Some(match &entry.outcome {
                OpOutcome::Success => "allowed".to_string(),
                OpOutcome::Denied => "denied".to_string(),
                OpOutcome::Pending => "pending_approval".to_string(),
                other => other.to_string(),
            }),
            compliance: Vec::new(),
            merkle_root: entry.merkle_root.clone(),
            audit_id: Some(entry.audit_id.clone()),
            children: Vec::new(),
        }
    }
}

// ─── OTel Export ─────────────────────────────────────────────────

impl Span {
    /// Convert to OTel-compatible JSON span.
    pub fn to_otel(&self) -> serde_json::Value {
        let mut attrs = serde_json::json!({
            "gen_ai.operation.name": self.otel_operation_name(),
        });

        if let Some(name) = &self.agent_name {
            attrs["gen_ai.agent.name"] = serde_json::json!(name);
        }
        if let Some(id) = &self.agent_id {
            attrs["gen_ai.agent.id"] = serde_json::json!(id);
        }
        if let Some(model) = &self.model {
            attrs["gen_ai.request.model"] = serde_json::json!(model);
        }
        if let Some(provider) = &self.provider {
            attrs["gen_ai.provider.name"] = serde_json::json!(provider);
        }
        if let Some(cid) = &self.cid {
            attrs["connector.cid"] = serde_json::json!(cid);
        }
        if let Some(label) = &self.cid_label {
            attrs["connector.cid_label"] = serde_json::json!(label);
        }
        if let Some(trust) = self.trust_score {
            attrs["connector.trust_score"] = serde_json::json!(trust);
        }
        if !self.compliance.is_empty() {
            attrs["connector.compliance"] = serde_json::json!(self.compliance);
        }
        if let Some(merkle) = &self.merkle_root {
            attrs["connector.merkle_root"] = serde_json::json!(merkle);
        }

        serde_json::json!({
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": "INTERNAL",
            "start_time": self.started_at,
            "end_time": self.ended_at,
            "status": { "code": match self.status {
                SpanStatus::Ok => "OK",
                SpanStatus::Error => "ERROR",
                _ => "UNSET",
            }},
            "attributes": attrs,
        })
    }

    fn otel_operation_name(&self) -> &str {
        match self.span_type {
            SpanType::Agent => "invoke_agent",
            SpanType::Generation => "chat",
            SpanType::ToolCall => "execute_tool",
            SpanType::MemoryWrite => "memory.write",
            SpanType::MemoryRead => "memory.read",
            SpanType::Guardrail => "guardrail",
            SpanType::Authorization => "authorize",
            SpanType::Handoff => "handoff",
            SpanType::Security => "security.verify",
            SpanType::Lifecycle => "agent.lifecycle",
            SpanType::Session => "session",
            SpanType::Access => "authorize",
            SpanType::Maintenance => "internal",
        }
    }
}

// ─── LLM View ────────────────────────────────────────────────────

impl Trace {
    /// Generate LLM-friendly structured summary.
    pub fn to_llm(&self) -> serde_json::Value {
        let steps: Vec<serde_json::Value> = self.summary.steps.iter().map(|s| {
            serde_json::json!({
                "step": s.step,
                "agent": s.agent,
                "action": s.action,
                "tools_used": s.tools_used,
                "authorization": s.authorization,
                "memories_used": s.memories_used,
                "duration_ms": s.duration_ms,
            })
        }).collect();

        serde_json::json!({
            "summary": self.summary.narrative,
            "pipeline": self.pipeline_name,
            "duration_ms": self.duration_ms,
            "status": format!("{:?}", self.status).to_lowercase(),
            "steps": steps,
            "trust": {
                "score": self.summary.trust_score,
                "grade": self.summary.trust_grade,
                "explanation": self.summary.trust_explanation,
            },
            "authorization": self.summary.authorization_summary,
            "compliance": self.summary.compliance,
            "counts": {
                "actors": self.summary.actors,
                "spans": self.summary.total_spans,
                "llm_calls": self.summary.llm_calls,
                "tool_calls": self.summary.tool_calls,
                "memory_ops": self.summary.memory_ops,
            },
            "tokens": self.summary.total_tokens,
            "cost_usd": self.summary.total_cost_usd,
        })
    }

    /// Generate OTel-compatible span array.
    pub fn to_otel_spans(&self) -> Vec<serde_json::Value> {
        self.spans.iter().map(|s| s.to_otel()).collect()
    }
}

// ─── Display Implementations ─────────────────────────────────────

impl std::fmt::Display for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = &self.summary;
        let bar = "═".repeat(62);

        // Header
        writeln!(f, "╔{}╗", bar)?;
        writeln!(f, "║  Pipeline: {:<20} │  Trust: {}/100 ({}) {}",
            truncate_str(&self.pipeline_name, 20),
            s.trust_score,
            s.trust_grade,
            trust_shield(s.trust_score),
        )?;
        writeln!(f, "║  Duration: {:<20} │  {} actors, {} spans",
            format!("{}ms", self.duration_ms),
            s.actors,
            s.total_spans,
        )?;
        writeln!(f, "╠{}╣", bar)?;

        // Steps
        if s.steps.is_empty() {
            writeln!(f, "║  (no actor steps recorded)")?;
        } else {
            for step in &s.steps {
                writeln!(f, "║")?;
                writeln!(f, "║  {}. Agent \"{}\" ({}ms)", step.step, step.agent, step.duration_ms)?;
                if step.memories_used > 0 {
                    writeln!(f, "║     ├─ 📖 Recalled {} memories", step.memories_used)?;
                }
                for tool in &step.tools_used {
                    writeln!(f, "║     ├─ 🔧 Tool: {}", tool)?;
                }
                writeln!(f, "║     └─ {} {}", status_icon(&step.authorization), step.authorization)?;
            }
        }

        // Memory operation spans
        let mem_writes: Vec<&Span> = self.spans.iter()
            .filter(|s| s.span_type == SpanType::MemoryWrite)
            .collect();
        let mem_reads: Vec<&Span> = self.spans.iter()
            .filter(|s| s.span_type == SpanType::MemoryRead)
            .collect();

        if !mem_writes.is_empty() || !mem_reads.is_empty() {
            writeln!(f, "║")?;
            writeln!(f, "║  Memory Operations:")?;
            for span in &mem_writes {
                let cid_display = span.cid.as_ref()
                    .map(|c| format!(" [{}:{}]", span.cid_label.as_deref().unwrap_or("cid"), truncate_cid(c)))
                    .unwrap_or_default();
                writeln!(f, "║     {} {}{}", span.status_emoji, span.name, cid_display)?;
            }
            for span in &mem_reads {
                writeln!(f, "║     {} {}", span.status_emoji, span.name)?;
            }
        }

        writeln!(f, "║")?;
        writeln!(f, "╠{}╣", bar)?;

        // Trust dimensions
        writeln!(f, "║  Trust: {}", s.trust_explanation)?;

        // Compliance
        if !s.compliance.is_empty() {
            let comp_str: Vec<String> = s.compliance.iter().map(|c| format!("{} ✓", c)).collect();
            writeln!(f, "║  Compliance: {}", comp_str.join("  "))?;
        }

        // Authorization
        writeln!(f, "║  Auth: {}", s.authorization_summary)?;
        writeln!(f, "╚{}╝", bar)?;

        Ok(())
    }
}

impl std::fmt::Display for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let type_icon = match self.span_type {
            SpanType::Agent => "🤖",
            SpanType::Generation => "💬",
            SpanType::ToolCall => "🔧",
            SpanType::MemoryWrite => "📝",
            SpanType::MemoryRead => "📖",
            SpanType::Guardrail => "🛡️",
            SpanType::Authorization => "🔐",
            SpanType::Handoff => "🔀",
            SpanType::Security => "🔒",
            SpanType::Lifecycle => "⚙️",
            SpanType::Session => "📋",
            SpanType::Access => "🔑",
            SpanType::Maintenance => "🧹",
        };

        write!(f, "{} {} {} ({}ms)", self.status_emoji, type_icon, self.name, self.duration_ms)?;

        if let Some(cid) = &self.cid {
            write!(f, " [{}:{}]",
                self.cid_label.as_deref().unwrap_or("cid"),
                truncate_cid(cid)
            )?;
        }

        Ok(())
    }
}

impl std::fmt::Display for TraceSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.narrative)?;
        writeln!(f, "Trust: {}/100 ({}) — {}", self.trust_score, self.trust_grade, self.trust_explanation)?;
        if !self.compliance.is_empty() {
            writeln!(f, "Compliance: {}", self.compliance.join(", "))?;
        }
        write!(f, "Auth: {}", self.authorization_summary)?;
        Ok(())
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}...", &s[..max-3]) }
}

fn truncate_cid(cid: &str) -> String {
    if cid.len() <= 16 { cid.to_string() }
    else { format!("{}...{}", &cid[..8], &cid[cid.len()-4..]) }
}

fn trust_shield(score: u32) -> &'static str {
    if score >= 90 { "🛡️" }
    else if score >= 70 { "🔵" }
    else if score >= 50 { "🟡" }
    else { "🔴" }
}

fn status_icon(auth: &str) -> &'static str {
    if auth.contains("denied") { "❌" }
    else if auth.contains("pending") { "⏳" }
    else { "✅" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{SyscallRequest, SyscallPayload, SyscallValue};

    fn setup_kernel_with_agent() -> (MemoryKernel, String) {
        let mut kernel = MemoryKernel::new();

        let reg = SyscallRequest {
            agent_pid: "system".to_string(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "triage".to_string(),
                namespace: "ns:hospital".to_string(),
                role: Some("writer".to_string()),
                model: None,
                framework: None,
            },
            reason: None,
            vakya_id: None,
        };
        let result = kernel.dispatch(reg);
        let pid = match result.value {
            SyscallValue::AgentPid(p) => p,
            _ => panic!("Expected AgentPid"),
        };

        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        });

        (kernel, pid)
    }

    #[test]
    fn test_op_to_human() {
        assert_eq!(op_to_human(&MemoryKernelOp::MemWrite), "Stored memory");
        assert_eq!(op_to_human(&MemoryKernelOp::AgentRegister), "Registered agent");
        assert_eq!(op_to_human(&MemoryKernelOp::ToolDispatch), "Called tool");
        assert_eq!(op_to_human(&MemoryKernelOp::IntegrityCheck), "Verified integrity");
    }

    #[test]
    fn test_op_to_llm() {
        assert_eq!(op_to_llm(&MemoryKernelOp::MemWrite), "memory_stored");
        assert_eq!(op_to_llm(&MemoryKernelOp::AgentStart), "agent_started");
        assert_eq!(op_to_llm(&MemoryKernelOp::AccessGrant), "access_granted");
    }

    #[test]
    fn test_outcome_emoji() {
        assert_eq!(outcome_emoji(&OpOutcome::Success), "✅");
        assert_eq!(outcome_emoji(&OpOutcome::Denied), "❌");
        assert_eq!(outcome_emoji(&OpOutcome::Pending), "⏳");
    }

    #[test]
    fn test_span_type_classification() {
        assert_eq!(op_to_span_type(&MemoryKernelOp::MemWrite), SpanType::MemoryWrite);
        assert_eq!(op_to_span_type(&MemoryKernelOp::MemRead), SpanType::MemoryRead);
        assert_eq!(op_to_span_type(&MemoryKernelOp::AgentRegister), SpanType::Lifecycle);
        assert_eq!(op_to_span_type(&MemoryKernelOp::ToolDispatch), SpanType::ToolCall);
        assert_eq!(op_to_span_type(&MemoryKernelOp::AccessGrant), SpanType::Access);
    }

    #[test]
    fn test_trace_from_kernel() {
        let (kernel, _pid) = setup_kernel_with_agent();

        let trust_dims = crate::trust::TrustDimensions {
            memory_integrity: 18,
            audit_completeness: 20,
            authorization_coverage: 17,
            decision_provenance: 18,
            operational_health: 16,
            claim_validity: None,
        };

        let trace = TraceBuilder::from_kernel(
            &kernel,
            "hospital-er",
            "trace_test001",
            &["triage".to_string()],
            &["hipaa".to_string()],
            245,
            89,
            "A",
            &trust_dims,
        );

        assert_eq!(trace.trace_id, "trace_test001");
        assert_eq!(trace.pipeline_name, "hospital-er");
        assert_eq!(trace.duration_ms, 245);
        assert_eq!(trace.status, SpanStatus::Ok);
        assert!(trace.spans.len() >= 2); // register + start
        assert_eq!(trace.summary.actors, 1);
        assert_eq!(trace.summary.trust_score, 89);
        assert_eq!(trace.summary.trust_grade, "A");
        assert!(trace.summary.trust_explanation.contains("18/20 memory integrity"));
        assert!(trace.summary.narrative.contains("triage"));
        assert!(trace.summary.compliance.contains(&"hipaa".to_string()));
    }

    #[test]
    fn test_span_has_human_readable_name() {
        let (kernel, _pid) = setup_kernel_with_agent();
        let audit_log = kernel.audit_log();

        let span = TraceBuilder::entry_to_span(&audit_log[0], "trace_test", 0);
        // First entry is AgentRegister
        assert!(span.name.contains("Registered agent"));
        assert_eq!(span.status_emoji, "✅");
        assert_eq!(span.status, SpanStatus::Ok);
    }

    #[test]
    fn test_otel_export() {
        let (kernel, _pid) = setup_kernel_with_agent();
        let audit_log = kernel.audit_log();

        let span = TraceBuilder::entry_to_span(&audit_log[0], "trace_otel", 0);
        let otel = span.to_otel();

        assert_eq!(otel["trace_id"], "trace_otel");
        assert_eq!(otel["span_id"], "span_0000");
        assert!(otel["attributes"]["gen_ai.operation.name"].is_string());
        assert_eq!(otel["status"]["code"], "OK");
    }

    #[test]
    fn test_llm_view() {
        let (kernel, _pid) = setup_kernel_with_agent();

        let trust_dims = crate::trust::TrustDimensions {
            memory_integrity: 20,
            audit_completeness: 20,
            authorization_coverage: 20,
            decision_provenance: 20,
            operational_health: 20,
            claim_validity: None,
        };

        let trace = TraceBuilder::from_kernel(
            &kernel,
            "test-pipe",
            "trace_llm",
            &["bot".to_string()],
            &[],
            100,
            100,
            "A+",
            &trust_dims,
        );

        let llm = trace.to_llm();
        assert!(llm["summary"].as_str().unwrap().contains("bot"));
        assert_eq!(llm["trust"]["score"], 100);
        assert_eq!(llm["trust"]["grade"], "A+");
        assert!(llm["trust"]["explanation"].as_str().unwrap().contains("20/20"));
        assert_eq!(llm["counts"]["actors"], 1);
    }

    #[test]
    fn test_otel_spans_array() {
        let (kernel, _pid) = setup_kernel_with_agent();

        let trust_dims = crate::trust::TrustDimensions {
            memory_integrity: 20,
            audit_completeness: 20,
            authorization_coverage: 20,
            decision_provenance: 20,
            operational_health: 20,
            claim_validity: None,
        };

        let trace = TraceBuilder::from_kernel(
            &kernel,
            "test-pipe",
            "trace_otel_arr",
            &[],
            &[],
            50,
            95,
            "A+",
            &trust_dims,
        );

        let otel_spans = trace.to_otel_spans();
        assert!(otel_spans.len() >= 2);
        for span in &otel_spans {
            assert_eq!(span["trace_id"], "trace_otel_arr");
            assert!(span["attributes"]["gen_ai.operation.name"].is_string());
        }
    }

    #[test]
    fn test_cid_label_detection() {
        let entry = KernelAuditEntry {
            audit_id: "audit:test".to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:test".to_string(),
            target: Some("bafy2bzacetest123".to_string()),
            outcome: OpOutcome::Success,
            reason: None,
            error: None,
            duration_us: Some(500),
            vakya_id: None,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
        };

        let span = TraceBuilder::entry_to_span(&entry, "trace_cid", 0);
        assert_eq!(span.cid_label.as_deref(), Some("memory"));
        assert!(span.name.contains("Stored memory"));
    }
}
