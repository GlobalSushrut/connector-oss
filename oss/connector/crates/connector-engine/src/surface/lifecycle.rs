//! Agent Lifecycle Tracing Surface — Birth→Run→Pause→Terminate with full trace
//!
//! Surfaces for viewing agent lifecycle events and state transitions.

use super::document::*;
use serde::{Deserialize, Serialize};

/// Agent lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleState {
    /// Agent registered but not started
    Registered,
    /// Agent initializing (loading contract, capabilities)
    Initializing,
    /// Agent running and accepting work
    Running,
    /// Agent paused (can resume)
    Paused,
    /// Agent suspended (needs approval to resume)
    Suspended,
    /// Agent migrating to another cell
    Migrating,
    /// Agent terminating (cleanup in progress)
    Terminating,
    /// Agent terminated (final state)
    Terminated,
    /// Agent failed (error state)
    Failed,
}

impl LifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registered => "REGISTERED",
            Self::Initializing => "INITIALIZING",
            Self::Running => "RUNNING",
            Self::Paused => "PAUSED",
            Self::Suspended => "SUSPENDED",
            Self::Migrating => "MIGRATING",
            Self::Terminating => "TERMINATING",
            Self::Terminated => "TERMINATED",
            Self::Failed => "FAILED",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::Running => Severity::Ok,
            Self::Registered | Self::Initializing => Severity::Info,
            Self::Paused | Self::Migrating => Severity::Warn,
            Self::Suspended | Self::Terminating => Severity::Risk,
            Self::Terminated | Self::Failed => Severity::Critical,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated | Self::Failed)
    }

    pub fn can_transition_to(&self, next: LifecycleState) -> bool {
        match self {
            Self::Registered => matches!(next, Self::Initializing | Self::Terminated),
            Self::Initializing => matches!(next, Self::Running | Self::Failed),
            Self::Running => matches!(next, Self::Paused | Self::Suspended | Self::Migrating | Self::Terminating),
            Self::Paused => matches!(next, Self::Running | Self::Terminating),
            Self::Suspended => matches!(next, Self::Running | Self::Terminating),
            Self::Migrating => matches!(next, Self::Running | Self::Failed),
            Self::Terminating => matches!(next, Self::Terminated | Self::Failed),
            Self::Terminated | Self::Failed => false,
        }
    }
}

/// Lifecycle event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub event_id: String,
    pub agent_pid: String,
    pub from_state: LifecycleState,
    pub to_state: LifecycleState,
    pub timestamp: i64,
    pub trigger: LifecycleTrigger,
    pub actor: String,
    pub reason: Option<String>,
    pub duration_ms: Option<u64>,
    pub evidence_cid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleTrigger {
    /// User/operator initiated
    Manual,
    /// System/scheduler initiated
    System,
    /// Policy enforcement
    Policy,
    /// Resource limit exceeded
    ResourceLimit,
    /// Error/failure
    Error,
    /// Contract completion
    ContractComplete,
    /// Migration request
    Migration,
    /// Watchdog action
    Watchdog,
}

/// Full lifecycle trace for an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTrace {
    pub agent_pid: String,
    pub current_state: LifecycleState,
    pub events: Vec<LifecycleEvent>,
    pub created_at: i64,
    pub last_transition_at: i64,
    pub total_runtime_ms: u64,
    pub total_paused_ms: u64,
    pub restart_count: u32,
    pub migration_count: u32,
}

impl LifecycleTrace {
    pub fn uptime_percent(&self) -> f64 {
        let total = self.total_runtime_ms + self.total_paused_ms;
        if total == 0 { 0.0 } else { (self.total_runtime_ms as f64 / total as f64) * 100.0 }
    }

    pub fn state_durations(&self) -> std::collections::HashMap<String, u64> {
        let mut durations = std::collections::HashMap::new();
        for i in 0..self.events.len() {
            let event = &self.events[i];
            let duration = if i + 1 < self.events.len() {
                self.events[i + 1].timestamp - event.timestamp
            } else {
                chrono::Utc::now().timestamp_millis() - event.timestamp
            };
            *durations.entry(event.to_state.as_str().to_string()).or_default() += duration as u64;
        }
        durations
    }
}

/// Build lifecycle trace surface
pub fn build_lifecycle_surface(trace: &LifecycleTrace, view: SurfaceView) -> SurfaceDocument {
    let state_severity = trace.current_state.severity();
    let uptime = trace.uptime_percent();

    let mut sections = vec![
        SurfaceSection {
            title: "Lifecycle Summary".into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(vec![
                StatItem { label: "Current State".into(), value: trace.current_state.as_str().into(), link: None },
                StatItem { label: "Uptime".into(), value: format!("{:.1}%", uptime), link: None },
                StatItem { label: "Runtime".into(), value: format!("{:.1}h", trace.total_runtime_ms as f64 / 3_600_000.0), link: None },
                StatItem { label: "Restarts".into(), value: trace.restart_count.to_string(), link: None },
                StatItem { label: "Migrations".into(), value: trace.migration_count.to_string(), link: None },
                StatItem { label: "Events".into(), value: trace.events.len().to_string(), link: None },
            ]),
            collapsed: false,
        },
    ];

    // Timeline of events
    let timeline_events: Vec<TimelineEvent> = trace.events.iter().rev().take(20).map(|e| {
        let ts = chrono::DateTime::from_timestamp_millis(e.timestamp)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| e.timestamp.to_string());
        TimelineEvent {
            timestamp: ts,
            event_type: format!("{:?}", e.trigger),
            message: format!("{} → {} ({})", e.from_state.as_str(), e.to_state.as_str(), 
                e.reason.as_deref().unwrap_or("no reason")),
            severity: e.to_state.severity(),
            link: e.evidence_cid.as_ref().map(|cid| ResourceLink::verify(ResourceKind::Proof, cid)),
        }
    }).collect();

    sections.push(SurfaceSection {
        title: "Lifecycle Timeline".into(),
        kind: SectionKind::Timeline,
        content: SectionContent::Timeline(timeline_events),
        collapsed: false,
    });

    if view == SurfaceView::Forensic {
        // State duration breakdown
        let durations = trace.state_durations();
        sections.push(SurfaceSection {
            title: "State Durations".into(),
            kind: SectionKind::KeyValueTable,
            content: SectionContent::KeyValue(durations.iter().map(|(state, dur)| KeyValueItem {
                key: state.clone(),
                value: format!("{:.1}h", *dur as f64 / 3_600_000.0),
                link: None,
            }).collect()),
            collapsed: false,
        });
    }

    SurfaceDocument {
        meta: SurfaceMeta {
            surface_type: SurfaceType::Trace,
            view,
            generated_at: chrono::Utc::now().timestamp_millis(),
        },
        header: SurfaceHeader {
            title: format!("LIFECYCLE: {}", trace.agent_pid),
            subject: SubjectIdentity::new(ResourceKind::Agent, &trace.agent_pid),
            state: StateVector {
                execution: match trace.current_state {
                    LifecycleState::Running => ExecutionState::Active,
                    LifecycleState::Paused | LifecycleState::Suspended => ExecutionState::Paused,
                    LifecycleState::Terminated | LifecycleState::Failed => ExecutionState::Failed,
                    _ => ExecutionState::Idle,
                },
                trust: TrustState::Verified,
                health: if trace.current_state == LifecycleState::Running { HealthState::Healthy } else { HealthState::Degraded },
                compliance: ComplianceState::Compliant,
            },
            badges: vec![
                SurfaceBadge { label: "State".into(), value: trace.current_state.as_str().into(), severity: state_severity },
                SurfaceBadge { label: "Uptime".into(), value: format!("{:.0}%", uptime), severity: if uptime > 95.0 { Severity::Ok } else { Severity::Warn } },
                SurfaceBadge { label: "Events".into(), value: trace.events.len().to_string(), severity: Severity::Info },
            ],
            time_range: Some(format!("since {}", chrono::DateTime::from_timestamp_millis(trace.created_at)
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_default())),
        },
        summary: Some(format!("Agent {} in {} state with {} lifecycle events",
            trace.agent_pid, trace.current_state.as_str(), trace.events.len())),
        sections,
        actions: vec![
            SurfaceAction { label: "Pause".into(), description: "Pause agent".into(), command: format!("connectorctl agent pause {}", trace.agent_pid), primary: false },
            SurfaceAction { label: "Resume".into(), description: "Resume agent".into(), command: format!("connectorctl agent resume {}", trace.agent_pid), primary: false },
            SurfaceAction { label: "Terminate".into(), description: "Terminate agent".into(), command: format!("connectorctl agent terminate {}", trace.agent_pid), primary: false },
        ],
        footer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_state_transitions() {
        assert!(LifecycleState::Registered.can_transition_to(LifecycleState::Initializing));
        assert!(LifecycleState::Running.can_transition_to(LifecycleState::Paused));
        assert!(!LifecycleState::Terminated.can_transition_to(LifecycleState::Running));
    }

    #[test]
    fn test_lifecycle_surface() {
        let trace = LifecycleTrace {
            agent_pid: "claims-agent".into(),
            current_state: LifecycleState::Running,
            events: vec![
                LifecycleEvent {
                    event_id: "evt-001".into(),
                    agent_pid: "claims-agent".into(),
                    from_state: LifecycleState::Registered,
                    to_state: LifecycleState::Initializing,
                    timestamp: chrono::Utc::now().timestamp_millis() - 3600000,
                    trigger: LifecycleTrigger::Manual,
                    actor: "user-1".into(),
                    reason: Some("Initial start".into()),
                    duration_ms: Some(1000),
                    evidence_cid: None,
                },
            ],
            created_at: chrono::Utc::now().timestamp_millis() - 3600000,
            last_transition_at: chrono::Utc::now().timestamp_millis(),
            total_runtime_ms: 3500000,
            total_paused_ms: 100000,
            restart_count: 0,
            migration_count: 0,
        };

        let doc = build_lifecycle_surface(&trace, SurfaceView::Ops);
        assert!(doc.header.title.contains("LIFECYCLE"));
    }
}
