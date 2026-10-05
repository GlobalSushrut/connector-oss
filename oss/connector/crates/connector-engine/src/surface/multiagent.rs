//! Multi-Agent Coordination Surface — Delegation, consensus, coordination output
//!
//! Surfaces for viewing multi-agent interactions in the distributed network.

use super::document::*;
use serde::{Deserialize, Serialize};

/// Multi-agent coordination pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinationPattern {
    /// One agent delegates to another
    Delegation,
    /// Multiple agents work in parallel
    Parallel,
    /// Agents form a pipeline
    Pipeline,
    /// Agents reach consensus
    Consensus,
    /// Saga with compensation
    Saga,
    /// Map-reduce pattern
    MapReduce,
    /// Broadcast to all
    Broadcast,
    /// Request-response
    RequestResponse,
}

impl CoordinationPattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Delegation => "DELEGATION",
            Self::Parallel => "PARALLEL",
            Self::Pipeline => "PIPELINE",
            Self::Consensus => "CONSENSUS",
            Self::Saga => "SAGA",
            Self::MapReduce => "MAP_REDUCE",
            Self::Broadcast => "BROADCAST",
            Self::RequestResponse => "REQUEST_RESPONSE",
        }
    }
}

/// Agent interaction in a coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInteraction {
    pub interaction_id: String,
    pub from_agent: String,
    pub to_agent: String,
    pub interaction_type: InteractionType,
    pub timestamp: i64,
    pub payload_cid: Option<String>,
    pub response_cid: Option<String>,
    pub latency_ms: Option<u64>,
    pub status: InteractionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionType {
    TaskDelegation,
    TaskResult,
    MemoryShare,
    KnowledgeRequest,
    KnowledgeResponse,
    ConsensusVote,
    ConsensusResult,
    Heartbeat,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionStatus {
    Pending,
    Sent,
    Acknowledged,
    Completed,
    Failed,
    Timeout,
}

/// Coordination session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationSession {
    pub session_id: String,
    pub pattern: CoordinationPattern,
    pub initiator: String,
    pub participants: Vec<String>,
    pub interactions: Vec<AgentInteraction>,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub status: CoordinationStatus,
    pub result_cid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinationStatus {
    Initializing,
    InProgress,
    WaitingForConsensus,
    Succeeded,
    Failed,
    PartialSuccess,
    RollingBack,
    RolledBack,
}

/// Consensus state for multi-agent decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    pub proposal_id: String,
    pub proposer: String,
    pub proposal_cid: String,
    pub votes: Vec<ConsensusVote>,
    pub required_votes: u32,
    pub deadline: i64,
    pub status: ConsensusStatus,
    pub result: Option<ConsensusResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    pub voter: String,
    pub vote: VoteType,
    pub timestamp: i64,
    pub reason: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusStatus {
    Voting,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub approved: bool,
    pub approve_count: u32,
    pub reject_count: u32,
    pub abstain_count: u32,
    pub finalized_at: i64,
}

/// Build coordination session surface
pub fn build_coordination_surface(session: &CoordinationSession, view: SurfaceView) -> SurfaceDocument {
    let status_severity = match session.status {
        CoordinationStatus::Succeeded => Severity::Ok,
        CoordinationStatus::InProgress | CoordinationStatus::Initializing | CoordinationStatus::WaitingForConsensus => Severity::Info,
        CoordinationStatus::PartialSuccess => Severity::Warn,
        CoordinationStatus::Failed | CoordinationStatus::RollingBack | CoordinationStatus::RolledBack => Severity::Critical,
    };

    let completed_interactions = session.interactions.iter()
        .filter(|i| i.status == InteractionStatus::Completed).count();
    let failed_interactions = session.interactions.iter()
        .filter(|i| i.status == InteractionStatus::Failed || i.status == InteractionStatus::Timeout).count();

    let duration_ms = session.completed_at.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()) - session.started_at;

    let mut sections = vec![
        SurfaceSection {
            title: "Coordination Summary".into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(vec![
                StatItem { label: "Pattern".into(), value: session.pattern.as_str().into(), link: None },
                StatItem { label: "Participants".into(), value: session.participants.len().to_string(), link: None },
                StatItem { label: "Interactions".into(), value: format!("{}/{} complete", completed_interactions, session.interactions.len()), link: None },
                StatItem { label: "Failed".into(), value: failed_interactions.to_string(), link: None },
                StatItem { label: "Duration".into(), value: format!("{:.1}s", duration_ms as f64 / 1000.0), link: None },
            ]),
            collapsed: false,
        },
    ];

    // Participant list
    sections.push(SurfaceSection {
        title: "Participants".into(),
        kind: SectionKind::List,
        content: SectionContent::List(session.participants.iter().map(|p| ListItem {
            text: if *p == session.initiator { format!("{} (initiator)", p) } else { p.clone() },
            link: Some(ResourceLink::inspect(ResourceKind::Agent, p)),
        }).collect()),
        collapsed: view == SurfaceView::Summary,
    });

    // Interaction timeline
    if view == SurfaceView::Ops || view == SurfaceView::Forensic {
        let timeline: Vec<TimelineEvent> = session.interactions.iter().map(|i| {
            let ts = chrono::DateTime::from_timestamp_millis(i.timestamp)
                .map(|dt| dt.format("%H:%M:%S.%3f").to_string())
                .unwrap_or_default();
            let severity = match i.status {
                InteractionStatus::Completed => Severity::Ok,
                InteractionStatus::Pending | InteractionStatus::Sent | InteractionStatus::Acknowledged => Severity::Info,
                InteractionStatus::Failed | InteractionStatus::Timeout => Severity::Critical,
            };
            TimelineEvent {
                timestamp: ts,
                event_type: format!("{:?}", i.interaction_type),
                message: format!("{} → {} ({:?})", i.from_agent, i.to_agent, i.status),
                severity,
                link: i.payload_cid.as_ref().map(|cid| ResourceLink::verify(ResourceKind::Proof, cid)),
            }
        }).collect();

        sections.push(SurfaceSection {
            title: "Interaction Timeline".into(),
            kind: SectionKind::Timeline,
            content: SectionContent::Timeline(timeline),
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
            title: format!("COORDINATION: {}", session.session_id),
            subject: SubjectIdentity {
                display: format!("coordination/{}", session.session_id),
                inspect: session.session_id.clone(),
                proof: format!("crd_{}", &session.session_id[..6.min(session.session_id.len())]),
                uid: session.session_id.clone(),
                kind: ResourceKind::Contract,
                namespace: None,
            },
            state: StateVector {
                execution: match session.status {
                    CoordinationStatus::InProgress | CoordinationStatus::WaitingForConsensus => ExecutionState::Active,
                    CoordinationStatus::Succeeded | CoordinationStatus::PartialSuccess => ExecutionState::Completed,
                    CoordinationStatus::Failed | CoordinationStatus::RolledBack => ExecutionState::Failed,
                    _ => ExecutionState::Idle,
                },
                trust: TrustState::Verified,
                health: if failed_interactions == 0 { HealthState::Healthy } else { HealthState::Degraded },
                compliance: ComplianceState::Compliant,
            },
            badges: vec![
                SurfaceBadge { label: "Pattern".into(), value: session.pattern.as_str().into(), severity: Severity::Info },
                SurfaceBadge { label: "Status".into(), value: format!("{:?}", session.status), severity: status_severity },
                SurfaceBadge { label: "Agents".into(), value: session.participants.len().to_string(), severity: Severity::Info },
            ],
            time_range: Some(format!("{:.1}s", duration_ms as f64 / 1000.0)),
        },
        summary: Some(format!("{} coordination with {} participants, {} interactions",
            session.pattern.as_str(), session.participants.len(), session.interactions.len())),
        sections,
        actions: vec![
            SurfaceAction { label: "Cancel".into(), description: "Cancel coordination".into(), command: format!("connectorctl coordination cancel {}", session.session_id), primary: false },
            SurfaceAction { label: "Trace".into(), description: "Full trace".into(), command: format!("connectorctl coordination trace {}", session.session_id), primary: true },
        ],
        footer: None,
    }
}

/// Build consensus surface
pub fn build_consensus_surface(consensus: &ConsensusState, view: SurfaceView) -> SurfaceDocument {
    let approve_count = consensus.votes.iter().filter(|v| v.vote == VoteType::Approve).count() as u32;
    let reject_count = consensus.votes.iter().filter(|v| v.vote == VoteType::Reject).count() as u32;
    let abstain_count = consensus.votes.iter().filter(|v| v.vote == VoteType::Abstain).count() as u32;

    let status_severity = match consensus.status {
        ConsensusStatus::Approved => Severity::Ok,
        ConsensusStatus::Voting => Severity::Info,
        ConsensusStatus::Rejected | ConsensusStatus::Expired | ConsensusStatus::Cancelled => Severity::Critical,
    };

    let progress = (consensus.votes.len() as f64 / consensus.required_votes as f64 * 100.0).min(100.0);

    SurfaceDocument {
        meta: SurfaceMeta {
            surface_type: SurfaceType::Review,
            view,
            generated_at: chrono::Utc::now().timestamp_millis(),
        },
        header: SurfaceHeader {
            title: format!("CONSENSUS: {}", consensus.proposal_id),
            subject: SubjectIdentity {
                display: format!("consensus/{}", consensus.proposal_id),
                inspect: consensus.proposal_id.clone(),
                proof: format!("con_{}", &consensus.proposal_id[..6.min(consensus.proposal_id.len())]),
                uid: consensus.proposal_id.clone(),
                kind: ResourceKind::Contract,
                namespace: None,
            },
            state: StateVector::active_verified(),
            badges: vec![
                SurfaceBadge { label: "Status".into(), value: format!("{:?}", consensus.status), severity: status_severity },
                SurfaceBadge { label: "Progress".into(), value: format!("{:.0}%", progress), severity: Severity::Info },
                SurfaceBadge { label: "Votes".into(), value: format!("{}/{}", consensus.votes.len(), consensus.required_votes), severity: Severity::Info },
            ],
            time_range: None,
        },
        summary: Some(format!("Consensus {} - {} approve, {} reject, {} abstain",
            consensus.proposal_id, approve_count, reject_count, abstain_count)),
        sections: vec![
            SurfaceSection {
                title: "Vote Summary".into(),
                kind: SectionKind::StatsGrid,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Approve".into(), value: approve_count.to_string(), link: None },
                    StatItem { label: "Reject".into(), value: reject_count.to_string(), link: None },
                    StatItem { label: "Abstain".into(), value: abstain_count.to_string(), link: None },
                    StatItem { label: "Required".into(), value: consensus.required_votes.to_string(), link: None },
                ]),
                collapsed: false,
            },
            SurfaceSection {
                title: "Votes".into(),
                kind: SectionKind::List,
                content: SectionContent::List(consensus.votes.iter().map(|v| ListItem {
                    text: format!("{}: {:?} {}", v.voter, v.vote, v.reason.as_deref().unwrap_or("")),
                    link: Some(ResourceLink::inspect(ResourceKind::Agent, &v.voter)),
                }).collect()),
                collapsed: false,
            },
        ],
        actions: vec![
            SurfaceAction { label: "Vote".into(), description: "Cast vote".into(), command: format!("connectorctl consensus vote {}", consensus.proposal_id), primary: true },
        ],
        footer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordination_surface() {
        let session = CoordinationSession {
            session_id: "coord-001".into(),
            pattern: CoordinationPattern::Delegation,
            initiator: "agent-1".into(),
            participants: vec!["agent-1".into(), "agent-2".into()],
            interactions: vec![
                AgentInteraction {
                    interaction_id: "int-001".into(),
                    from_agent: "agent-1".into(),
                    to_agent: "agent-2".into(),
                    interaction_type: InteractionType::TaskDelegation,
                    timestamp: chrono::Utc::now().timestamp_millis(),
                    payload_cid: Some("cid-001".into()),
                    response_cid: None,
                    latency_ms: Some(50),
                    status: InteractionStatus::Completed,
                },
            ],
            started_at: chrono::Utc::now().timestamp_millis() - 1000,
            completed_at: None,
            status: CoordinationStatus::InProgress,
            result_cid: None,
        };

        let doc = build_coordination_surface(&session, SurfaceView::Ops);
        assert!(doc.header.title.contains("COORDINATION"));
    }
}
