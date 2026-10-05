//! Agent Sandboxing Surface — Isolation, resource limits, capability attenuation
//!
//! Surfaces for viewing and managing agent sandboxes in the distributed network.

use super::document::*;
use serde::{Deserialize, Serialize};

/// Sandbox isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// No isolation (trusted system agents)
    None,
    /// Process-level isolation
    Process,
    /// Container-level isolation (cgroups, namespaces)
    Container,
    /// VM-level isolation (full hypervisor)
    Vm,
    /// WASM sandbox (memory-safe, capability-gated)
    Wasm,
}

impl IsolationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Process => "PROCESS",
            Self::Container => "CONTAINER",
            Self::Vm => "VM",
            Self::Wasm => "WASM",
        }
    }

    pub fn security_score(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Process => 40,
            Self::Container => 70,
            Self::Vm => 90,
            Self::Wasm => 85,
        }
    }
}

/// Resource limits for a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_cores: f64,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_bandwidth_kbps: u64,
    pub max_open_files: u32,
    pub max_processes: u32,
    pub max_connections: u32,
    pub token_budget: u64,
    pub cost_budget_usd: f64,
    pub time_budget_ms: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_cores: 1.0,
            memory_mb: 512,
            disk_mb: 1024,
            network_bandwidth_kbps: 10_000,
            max_open_files: 256,
            max_processes: 16,
            max_connections: 64,
            token_budget: 100_000,
            cost_budget_usd: 1.0,
            time_budget_ms: 300_000,
        }
    }
}

/// Resource usage snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_rx_kb: u64,
    pub network_tx_kb: u64,
    pub open_files: u32,
    pub processes: u32,
    pub connections: u32,
    pub tokens_used: u64,
    pub cost_usd: f64,
    pub runtime_ms: u64,
}

/// Capability granted to a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCapability {
    pub capability_id: String,
    pub capability_type: CapabilityType,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
    pub attenuated_from: Option<String>,
    pub delegation_depth: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityType {
    MemoryRead,
    MemoryWrite,
    ToolCall,
    NetworkAccess,
    FileRead,
    FileWrite,
    AgentSpawn,
    AgentMessage,
    SecretAccess,
    PolicyOverride,
}

impl CapabilityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MemoryRead => "memory:read",
            Self::MemoryWrite => "memory:write",
            Self::ToolCall => "tool:call",
            Self::NetworkAccess => "network:access",
            Self::FileRead => "file:read",
            Self::FileWrite => "file:write",
            Self::AgentSpawn => "agent:spawn",
            Self::AgentMessage => "agent:message",
            Self::SecretAccess => "secret:access",
            Self::PolicyOverride => "policy:override",
        }
    }

    pub fn risk_level(&self) -> Severity {
        match self {
            Self::MemoryRead | Self::FileRead => Severity::Info,
            Self::MemoryWrite | Self::FileWrite | Self::ToolCall => Severity::Warn,
            Self::NetworkAccess | Self::AgentMessage => Severity::Warn,
            Self::AgentSpawn | Self::SecretAccess => Severity::Risk,
            Self::PolicyOverride => Severity::Critical,
        }
    }
}

/// Full sandbox state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxState {
    pub sandbox_id: String,
    pub agent_pid: String,
    pub cell_id: String,
    pub isolation: IsolationLevel,
    pub limits: ResourceLimits,
    pub usage: ResourceUsage,
    pub capabilities: Vec<SandboxCapability>,
    pub created_at: i64,
    pub status: SandboxStatus,
    pub violations: Vec<SandboxViolation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxStatus {
    Initializing,
    Running,
    Paused,
    Throttled,
    Terminated,
    Violated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxViolation {
    pub violation_id: String,
    pub violation_type: ViolationType,
    pub timestamp: i64,
    pub detail: String,
    pub action_taken: ViolationAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationType {
    MemoryExceeded,
    CpuExceeded,
    TokenBudgetExceeded,
    CostBudgetExceeded,
    TimeBudgetExceeded,
    UnauthorizedCapability,
    NetworkViolation,
    FileSystemViolation,
    ProcessLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationAction {
    Warned,
    Throttled,
    Paused,
    Terminated,
    Logged,
}

/// Build sandbox surface document
pub fn build_sandbox_surface(state: &SandboxState, view: SurfaceView) -> SurfaceDocument {
    let usage_pct = |used: u64, limit: u64| -> f64 {
        if limit == 0 { 0.0 } else { (used as f64 / limit as f64) * 100.0 }
    };

    let mem_pct = usage_pct(state.usage.memory_mb, state.limits.memory_mb);
    let token_pct = usage_pct(state.usage.tokens_used, state.limits.token_budget);
    let cost_pct = (state.usage.cost_usd / state.limits.cost_budget_usd) * 100.0;

    let health_severity = if state.violations.is_empty() && mem_pct < 80.0 {
        Severity::Ok
    } else if mem_pct > 90.0 || !state.violations.is_empty() {
        Severity::Risk
    } else {
        Severity::Warn
    };

    let mut sections = vec![
        SurfaceSection {
            title: "Resource Usage".into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(vec![
                StatItem { label: "CPU".into(), value: format!("{:.1}%", state.usage.cpu_percent), link: None },
                StatItem { label: "Memory".into(), value: format!("{}/{} MB ({:.0}%)", state.usage.memory_mb, state.limits.memory_mb, mem_pct), link: None },
                StatItem { label: "Tokens".into(), value: format!("{}/{} ({:.0}%)", state.usage.tokens_used, state.limits.token_budget, token_pct), link: None },
                StatItem { label: "Cost".into(), value: format!("${:.4}/${:.2} ({:.0}%)", state.usage.cost_usd, state.limits.cost_budget_usd, cost_pct), link: None },
                StatItem { label: "Runtime".into(), value: format!("{:.1}s", state.usage.runtime_ms as f64 / 1000.0), link: None },
            ]),
            collapsed: false,
        },
    ];

    if view == SurfaceView::Ops || view == SurfaceView::Forensic {
        sections.push(SurfaceSection {
            title: "Capabilities".into(),
            kind: SectionKind::List,
            content: SectionContent::List(state.capabilities.iter().map(|c| ListItem {
                text: format!("{} (depth: {}, expires: {})", 
                    c.capability_type.as_str(), 
                    c.delegation_depth,
                    c.expires_at.map(|t| format!("{}ms", t)).unwrap_or("never".into())
                ),
                link: None,
            }).collect()),
            collapsed: false,
        });
    }

    if !state.violations.is_empty() {
        sections.push(SurfaceSection {
            title: "Violations".into(),
            kind: SectionKind::Findings,
            content: SectionContent::Findings(state.violations.iter().map(|v| Finding {
                severity: Severity::Risk,
                code: format!("{:?}", v.violation_type),
                message: format!("{} → {:?}", v.detail, v.action_taken),
                link: None,
            }).collect()),
            collapsed: false,
        });
    }

    SurfaceDocument {
        meta: SurfaceMeta {
            surface_type: SurfaceType::Agent,
            view,
            generated_at: chrono::Utc::now().timestamp_millis(),
        },
        header: SurfaceHeader {
            title: format!("SANDBOX: {}", state.agent_pid),
            subject: SubjectIdentity::new(ResourceKind::Agent, &state.agent_pid),
            state: StateVector {
                execution: match state.status {
                    SandboxStatus::Running => ExecutionState::Active,
                    SandboxStatus::Paused | SandboxStatus::Throttled => ExecutionState::Paused,
                    SandboxStatus::Terminated | SandboxStatus::Violated => ExecutionState::Failed,
                    SandboxStatus::Initializing => ExecutionState::Idle,
                },
                trust: TrustState::Verified,
                health: if state.violations.is_empty() { HealthState::Healthy } else { HealthState::Degraded },
                compliance: ComplianceState::Compliant,
            },
            badges: vec![
                SurfaceBadge { label: "Isolation".into(), value: state.isolation.as_str().into(), severity: Severity::Info },
                SurfaceBadge { label: "Status".into(), value: format!("{:?}", state.status), severity: health_severity },
                SurfaceBadge { label: "Cell".into(), value: state.cell_id.clone(), severity: Severity::Info },
            ],
            time_range: None,
        },
        summary: Some(format!("Sandbox {} with {} isolation, {} capabilities, {} violations",
            state.agent_pid, state.isolation.as_str(), state.capabilities.len(), state.violations.len())),
        sections,
        actions: vec![
            SurfaceAction { label: "Pause".into(), description: "Pause sandbox".into(), command: format!("connectorctl sandbox pause {}", state.sandbox_id), primary: false },
            SurfaceAction { label: "Terminate".into(), description: "Terminate sandbox".into(), command: format!("connectorctl sandbox terminate {}", state.sandbox_id), primary: false },
            SurfaceAction { label: "Inspect".into(), description: "Deep inspect".into(), command: format!("connectorctl sandbox inspect {}", state.sandbox_id), primary: true },
        ],
        footer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_surface() {
        let state = SandboxState {
            sandbox_id: "sb-001".into(),
            agent_pid: "claims-agent".into(),
            cell_id: "cell-us-east-1".into(),
            isolation: IsolationLevel::Container,
            limits: ResourceLimits::default(),
            usage: ResourceUsage {
                cpu_percent: 25.0,
                memory_mb: 256,
                disk_mb: 100,
                network_rx_kb: 1000,
                network_tx_kb: 500,
                open_files: 32,
                processes: 4,
                connections: 8,
                tokens_used: 50000,
                cost_usd: 0.25,
                runtime_ms: 60000,
            },
            capabilities: vec![
                SandboxCapability {
                    capability_id: "cap-001".into(),
                    capability_type: CapabilityType::MemoryRead,
                    granted_at: 0,
                    expires_at: None,
                    attenuated_from: None,
                    delegation_depth: 0,
                },
            ],
            created_at: 0,
            status: SandboxStatus::Running,
            violations: vec![],
        };

        let doc = build_sandbox_surface(&state, SurfaceView::Ops);
        assert!(doc.header.title.contains("SANDBOX"));
    }
}
