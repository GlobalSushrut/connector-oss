//! Workflow Builder DSL
//!
//! Fluent API for constructing workflows

use super::{Workflow, Step, Edge, WorkflowSettings, TriggerConfig};

pub struct WorkflowBuilder {
    workflow: Workflow,
}

impl WorkflowBuilder {
    pub fn new(tenant_id: &str, name: &str) -> Self {
        Self {
            workflow: Workflow {
                id: uuid::Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                name: name.to_string(),
                version: "1.0".to_string(),
                description: String::new(),
                steps: vec![],
                edges: vec![],
                triggers: vec![],
                variables: std::collections::HashMap::new(),
                settings: WorkflowSettings::default(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        }
    }
    
    pub fn description(mut self, desc: &str) -> Self {
        self.workflow.description = desc.to_string();
        self
    }
    
    pub fn build(self) -> Workflow {
        self.workflow
    }
}
