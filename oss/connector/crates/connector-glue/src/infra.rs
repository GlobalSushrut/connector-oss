use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineContract {
    pub id: String,
    pub agent: Option<String>,
    pub stages: Vec<PipelineStage>,
    pub rollback: bool,
    pub streaming: bool,
    pub audit_required: bool,
}

impl PipelineContract {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            agent: None,
            stages: Vec::new(),
            rollback: true,
            streaming: false,
            audit_required: true,
        }
    }

    pub fn agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = Some(agent.into());
        self
    }

    pub fn stage(mut self, stage: PipelineStage) -> Self {
        self.stages.push(stage);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStage {
    pub name: String,
    pub stage_type: PipelineStageType,
    pub target: String,
    pub required: bool,
}

impl PipelineStage {
    pub fn new(name: impl Into<String>, stage_type: PipelineStageType, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            stage_type,
            target: target.into(),
            required: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStageType {
    Memory,
    Knowledge,
    Tool,
    Policy,
    Protocol,
    Audit,
    Execution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContract {
    pub name: String,
    pub capability: Option<String>,
    pub firewall_checked: bool,
    pub rate_limited: bool,
    pub params_schema: Option<serde_json::Value>,
}

impl ToolContract {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capability: None,
            firewall_checked: true,
            rate_limited: true,
            params_schema: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContract {
    pub firewall_required: bool,
    pub guard_pipeline_required: bool,
    pub quota_enforced: bool,
    pub policy_enforced: bool,
    pub secret_isolation: bool,
    pub cross_cell_routing: bool,
}

impl Default for SecurityContract {
    fn default() -> Self {
        Self {
            firewall_required: true,
            guard_pipeline_required: true,
            quota_enforced: true,
            policy_enforced: true,
            secret_isolation: true,
            cross_cell_routing: false,
        }
    }
}
