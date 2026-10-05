//! Data Pipeline Surface — Input→Knowledge→Memory→Contract→Output (Kafka-style)
//!
//! Surfaces for viewing data architecture pipelines and flows.

use super::document::*;
use serde::{Deserialize, Serialize};

/// Pipeline stage type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    /// Raw input ingestion (/v/ assets)
    Ingestion,
    /// Data validation and cleaning
    Validation,
    /// Transformation and enrichment
    Transformation,
    /// Knowledge extraction (/k/ knowledge)
    KnowledgeExtraction,
    /// Memory storage (/m/ memory)
    MemoryStorage,
    /// Contract execution (CLS)
    ContractExecution,
    /// Output generation
    Output,
    /// Archival
    Archive,
}

impl PipelineStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ingestion => "INGESTION",
            Self::Validation => "VALIDATION",
            Self::Transformation => "TRANSFORM",
            Self::KnowledgeExtraction => "KNOWLEDGE",
            Self::MemoryStorage => "MEMORY",
            Self::ContractExecution => "CONTRACT",
            Self::Output => "OUTPUT",
            Self::Archive => "ARCHIVE",
        }
    }

    pub fn namespace_prefix(&self) -> &'static str {
        match self {
            Self::Ingestion => "/v/",
            Self::Validation => "/v/",
            Self::Transformation => "/v/",
            Self::KnowledgeExtraction => "/k/",
            Self::MemoryStorage => "/m/",
            Self::ContractExecution => "/c/",
            Self::Output => "/p/",
            Self::Archive => "/s/",
        }
    }
}

/// Pipeline definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDefinition {
    pub pipeline_id: String,
    pub name: String,
    pub stages: Vec<StageDefinition>,
    pub created_at: i64,
    pub version: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageDefinition {
    pub stage_id: String,
    pub stage_type: PipelineStage,
    pub config: serde_json::Value,
    pub timeout_ms: u64,
    pub retry_count: u32,
    pub dependencies: Vec<String>,
}

/// Pipeline execution instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineExecution {
    pub execution_id: String,
    pub pipeline_id: String,
    pub status: PipelineExecutionStatus,
    pub stages: Vec<StageExecution>,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub input_cid: String,
    pub output_cid: Option<String>,
    pub agent_pid: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineExecutionStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    RollingBack,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageExecution {
    pub stage_id: String,
    pub stage_type: PipelineStage,
    pub status: StageExecutionStatus,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub input_count: u64,
    pub output_count: u64,
    pub error_count: u64,
    pub throughput_per_sec: f64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageExecutionStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
    RolledBack,
}

/// Data flow metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowMetrics {
    pub pipeline_id: String,
    pub time_window_ms: u64,
    pub records_ingested: u64,
    pub records_validated: u64,
    pub records_transformed: u64,
    pub records_stored: u64,
    pub records_output: u64,
    pub validation_errors: u64,
    pub transform_errors: u64,
    pub avg_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub throughput_per_sec: f64,
}

/// Build pipeline execution surface
pub fn build_pipeline_surface(exec: &PipelineExecution, view: SurfaceView) -> SurfaceDocument {
    let status_severity = match exec.status {
        PipelineExecutionStatus::Succeeded => Severity::Ok,
        PipelineExecutionStatus::Running | PipelineExecutionStatus::Pending => Severity::Info,
        PipelineExecutionStatus::Failed | PipelineExecutionStatus::Cancelled => Severity::Critical,
        PipelineExecutionStatus::RollingBack | PipelineExecutionStatus::RolledBack => Severity::Warn,
    };

    let completed_stages = exec.stages.iter().filter(|s| s.status == StageExecutionStatus::Succeeded).count();
    let failed_stages = exec.stages.iter().filter(|s| s.status == StageExecutionStatus::Failed).count();

    let duration_ms = exec.completed_at.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()) - exec.started_at;

    let mut sections = vec![
        SurfaceSection {
            title: "Execution Summary".into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(vec![
                StatItem { label: "Status".into(), value: format!("{:?}", exec.status), link: None },
                StatItem { label: "Stages".into(), value: format!("{}/{} complete", completed_stages, exec.stages.len()), link: None },
                StatItem { label: "Failed".into(), value: failed_stages.to_string(), link: None },
                StatItem { label: "Duration".into(), value: format!("{:.1}s", duration_ms as f64 / 1000.0), link: None },
                StatItem { label: "Agent".into(), value: exec.agent_pid.clone(), link: Some(ResourceLink::inspect(ResourceKind::Agent, &exec.agent_pid)) },
            ]),
            collapsed: false,
        },
    ];

    // Stage timeline
    let stage_events: Vec<TimelineEvent> = exec.stages.iter().map(|s| {
        let ts = s.started_at.map(|t| {
            chrono::DateTime::from_timestamp_millis(t)
                .map(|dt| dt.format("%H:%M:%S").to_string())
                .unwrap_or_default()
        }).unwrap_or_else(|| "pending".into());

        let severity = match s.status {
            StageExecutionStatus::Succeeded => Severity::Ok,
            StageExecutionStatus::Running => Severity::Info,
            StageExecutionStatus::Failed => Severity::Critical,
            _ => Severity::Warn,
        };

        TimelineEvent {
            timestamp: ts,
            event_type: s.stage_type.as_str().into(),
            message: format!("{:?} - {} in, {} out, {} errors",
                s.status, s.input_count, s.output_count, s.error_count),
            severity,
            link: None,
        }
    }).collect();

    sections.push(SurfaceSection {
        title: "Stage Execution".into(),
        kind: SectionKind::Timeline,
        content: SectionContent::Timeline(stage_events),
        collapsed: false,
    });

    if view == SurfaceView::Forensic && exec.error.is_some() {
        sections.push(SurfaceSection {
            title: "Error Details".into(),
            kind: SectionKind::Narrative,
            content: SectionContent::Narrative(exec.error.clone().unwrap_or_default()),
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
            title: format!("PIPELINE: {}", exec.pipeline_id),
            subject: SubjectIdentity {
                display: format!("pipeline/{}", exec.execution_id),
                inspect: exec.execution_id.clone(),
                proof: format!("pip_{}", &exec.execution_id[..6.min(exec.execution_id.len())]),
                uid: exec.execution_id.clone(),
                kind: ResourceKind::Contract,
                namespace: None,
            },
            state: StateVector {
                execution: match exec.status {
                    PipelineExecutionStatus::Running => ExecutionState::Active,
                    PipelineExecutionStatus::Succeeded => ExecutionState::Completed,
                    PipelineExecutionStatus::Failed => ExecutionState::Failed,
                    _ => ExecutionState::Idle,
                },
                trust: TrustState::Verified,
                health: if failed_stages == 0 { HealthState::Healthy } else { HealthState::Degraded },
                compliance: ComplianceState::Compliant,
            },
            badges: vec![
                SurfaceBadge { label: "Status".into(), value: format!("{:?}", exec.status), severity: status_severity },
                SurfaceBadge { label: "Stages".into(), value: format!("{}/{}", completed_stages, exec.stages.len()), severity: Severity::Info },
            ],
            time_range: Some(format!("{:.1}s", duration_ms as f64 / 1000.0)),
        },
        summary: Some(format!("Pipeline {} execution {} - {} stages, {} completed",
            exec.pipeline_id, exec.execution_id, exec.stages.len(), completed_stages)),
        sections,
        actions: vec![
            SurfaceAction { label: "Cancel".into(), description: "Cancel execution".into(), command: format!("connectorctl pipeline cancel {}", exec.execution_id), primary: false },
            SurfaceAction { label: "Retry".into(), description: "Retry failed stages".into(), command: format!("connectorctl pipeline retry {}", exec.execution_id), primary: false },
            SurfaceAction { label: "Logs".into(), description: "View logs".into(), command: format!("connectorctl pipeline logs {}", exec.execution_id), primary: true },
        ],
        footer: None,
    }
}

/// Build data flow metrics surface
pub fn build_dataflow_surface(metrics: &DataFlowMetrics, view: SurfaceView) -> SurfaceDocument {
    let error_rate = if metrics.records_ingested > 0 {
        ((metrics.validation_errors + metrics.transform_errors) as f64 / metrics.records_ingested as f64) * 100.0
    } else {
        0.0
    };

    let health = if error_rate < 1.0 { Severity::Ok } else if error_rate < 5.0 { Severity::Warn } else { Severity::Critical };

    SurfaceDocument {
        meta: SurfaceMeta {
            surface_type: SurfaceType::Monitor,
            view,
            generated_at: chrono::Utc::now().timestamp_millis(),
        },
        header: SurfaceHeader {
            title: format!("DATAFLOW: {}", metrics.pipeline_id),
            subject: SubjectIdentity {
                display: format!("dataflow/{}", metrics.pipeline_id),
                inspect: metrics.pipeline_id.clone(),
                proof: format!("dfl_{}", &metrics.pipeline_id[..6.min(metrics.pipeline_id.len())]),
                uid: metrics.pipeline_id.clone(),
                kind: ResourceKind::Contract,
                namespace: None,
            },
            state: StateVector::active_verified(),
            badges: vec![
                SurfaceBadge { label: "Throughput".into(), value: format!("{:.1}/s", metrics.throughput_per_sec), severity: Severity::Info },
                SurfaceBadge { label: "Error Rate".into(), value: format!("{:.2}%", error_rate), severity: health },
                SurfaceBadge { label: "P99 Latency".into(), value: format!("{}ms", metrics.p99_latency_ms), severity: Severity::Info },
            ],
            time_range: Some(format!("last {}s", metrics.time_window_ms / 1000)),
        },
        summary: Some(format!("{} records processed, {:.1}/s throughput, {:.2}% error rate",
            metrics.records_ingested, metrics.throughput_per_sec, error_rate)),
        sections: vec![
            SurfaceSection {
                title: "Flow Metrics".into(),
                kind: SectionKind::StatsGrid,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Ingested".into(), value: metrics.records_ingested.to_string(), link: None },
                    StatItem { label: "Validated".into(), value: metrics.records_validated.to_string(), link: None },
                    StatItem { label: "Transformed".into(), value: metrics.records_transformed.to_string(), link: None },
                    StatItem { label: "Stored".into(), value: metrics.records_stored.to_string(), link: None },
                    StatItem { label: "Output".into(), value: metrics.records_output.to_string(), link: None },
                ]),
                collapsed: false,
            },
            SurfaceSection {
                title: "Error Breakdown".into(),
                kind: SectionKind::KeyValueTable,
                content: SectionContent::KeyValue(vec![
                    KeyValueItem { key: "Validation Errors".into(), value: metrics.validation_errors.to_string(), link: None },
                    KeyValueItem { key: "Transform Errors".into(), value: metrics.transform_errors.to_string(), link: None },
                    KeyValueItem { key: "Total Error Rate".into(), value: format!("{:.2}%", error_rate), link: None },
                ]),
                collapsed: false,
            },
            SurfaceSection {
                title: "Latency".into(),
                kind: SectionKind::KeyValueTable,
                content: SectionContent::KeyValue(vec![
                    KeyValueItem { key: "Average".into(), value: format!("{}ms", metrics.avg_latency_ms), link: None },
                    KeyValueItem { key: "P99".into(), value: format!("{}ms", metrics.p99_latency_ms), link: None },
                ]),
                collapsed: false,
            },
        ],
        actions: vec![
            SurfaceAction { label: "Refresh".into(), description: "Refresh metrics".into(), command: format!("connectorctl dataflow metrics {}", metrics.pipeline_id), primary: true },
        ],
        footer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_surface() {
        let exec = PipelineExecution {
            execution_id: "exec-001".into(),
            pipeline_id: "claims-pipeline".into(),
            status: PipelineExecutionStatus::Running,
            stages: vec![
                StageExecution {
                    stage_id: "s1".into(),
                    stage_type: PipelineStage::Ingestion,
                    status: StageExecutionStatus::Succeeded,
                    started_at: Some(chrono::Utc::now().timestamp_millis() - 5000),
                    completed_at: Some(chrono::Utc::now().timestamp_millis() - 4000),
                    input_count: 100,
                    output_count: 100,
                    error_count: 0,
                    throughput_per_sec: 100.0,
                    error: None,
                },
            ],
            started_at: chrono::Utc::now().timestamp_millis() - 5000,
            completed_at: None,
            input_cid: "cid-input".into(),
            output_cid: None,
            agent_pid: "pipeline-agent".into(),
            error: None,
        };

        let doc = build_pipeline_surface(&exec, SurfaceView::Ops);
        assert!(doc.header.title.contains("PIPELINE"));
    }
}
