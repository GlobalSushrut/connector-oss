use super::*;
use crate::error::AppError;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

pub struct WorkflowEngine {
    running: Arc<RwLock<HashMap<String, WorkflowRun>>>,
}

impl WorkflowEngine {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn start(&self, workflow: &Workflow, input: serde_json::Value) -> Result<WorkflowRun, AppError> {
        let run_id = uuid::Uuid::new_v4().to_string();
        let run = WorkflowRun {
            id: run_id,
            workflow_id: workflow.id.clone(),
            tenant_id: workflow.tenant_id.clone(),
            status: RunStatus::Running,
            input,
            output: None,
            step_results: HashMap::new(),
            current_step: None,
            started_at: Utc::now(),
            completed_at: None,
            error: None,
        };
        Ok(run)
    }
}
