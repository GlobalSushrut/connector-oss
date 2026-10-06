//! Workflow Triggers
//!
//! Handles HTTP webhooks, schedules, message queues, and event-based triggers

use super::{Workflow, TriggerConfig, TriggerType, TriggerTypeConfig};
use crate::error::AppError;
use sqlx::PgPool;
use serde_json::Value;
use tracing::{info, debug, error};
use chrono::Utc;

/// Trigger manager handles workflow activation
pub struct TriggerManager {
    pool: PgPool,
}

impl TriggerManager {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Check if a workflow should trigger based on event
    pub async fn check_trigger(
        &self,
        workflow: &Workflow,
        event_type: &str,
        event_data: &Value,
    ) -> Result<bool, AppError> {
        for trigger in &workflow.triggers {
            match &trigger.config {
                TriggerTypeConfig::Event { event_type: config_event, filter } => {
                    if config_event == event_type {
                        // Check filter if present
                        if self.matches_filter(event_data, filter) {
                            return Ok(true);
                        }
                    }
                }
                TriggerTypeConfig::Http { .. } => {
                    return Ok(true);
                }
                _ => {}
            }
        }
        
        Ok(false)
    }
    
    /// Log trigger event
    pub async fn log_trigger(
        &self,
        workflow_id: &str,
        trigger_type: &str,
        event_data: &Value,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO workflow_trigger_logs (id, workflow_id, trigger_type, event_data, triggered_at)
            VALUES ($1, $2, $3, $4, NOW())
            "#
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(workflow_id)
        .bind(trigger_type)
        .bind(event_data)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        debug!("Logged trigger for workflow: {}", workflow_id);
        Ok(())
    }
    
    /// Get pending scheduled workflows
    pub async fn get_pending_schedules(&self) -> Result<Vec<(Workflow, chrono::DateTime<chrono::Utc>)>, AppError> {
        // Query workflows with schedule triggers that are due
        let rows = sqlx::query_as::<_, WorkflowScheduleRow>(
            r#"
            SELECT w.id, w.tenant_id, w.name, w.version, w.description, 
                   w.definition, w.triggers, w.variables, w.settings,
                   s.next_run_at
            FROM workflows w
            JOIN workflow_schedules s ON s.workflow_id = w.id
            WHERE w.is_active = true 
              AND s.next_run_at <= NOW()
              AND s.is_active = true
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        let mut result = Vec::new();
        for row in rows {
            let workflow = Workflow {
                id: row.id.clone(),
                tenant_id: row.tenant_id,
                name: row.name,
                version: row.version,
                description: row.description.unwrap_or_default(),
                steps: serde_json::from_value(row.definition.get("steps").cloned().unwrap_or(serde_json::Value::Null))
                    .unwrap_or_default(),
                edges: serde_json::from_value(row.definition.get("edges").cloned().unwrap_or(serde_json::Value::Null))
                    .unwrap_or_default(),
                triggers: serde_json::from_value(row.triggers).unwrap_or_default(),
                variables: serde_json::from_value(row.variables).unwrap_or_default(),
                settings: serde_json::from_value(row.settings).unwrap_or_default(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            result.push((workflow, row.next_run_at));
        }
        
        Ok(result)
    }
    
    /// Update next run time for scheduled workflow
    pub async fn update_schedule(&self, workflow_id: &str, cron: &str) -> Result<(), AppError> {
        // Parse cron and calculate next run
        let next_run = self.calculate_next_run(cron)?;
        
        sqlx::query(
            r#"
            INSERT INTO workflow_schedules (workflow_id, cron, next_run_at, is_active)
            VALUES ($1, $2, $3, true)
            ON CONFLICT (workflow_id) DO UPDATE SET
                cron = EXCLUDED.cron,
                next_run_at = EXCLUDED.next_run_at,
                updated_at = NOW()
            "#
        )
        .bind(workflow_id)
        .bind(cron)
        .bind(next_run)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        Ok(())
    }
    
    /// Check if event matches filter
    fn matches_filter(&self, event: &Value, filter: &Value) -> bool {
        // Simple JSON matching - in production use JSONPath or jq
        if let (Some(event_obj), Some(filter_obj)) = (event.as_object(), filter.as_object()) {
            for (key, filter_val) in filter_obj {
                match event_obj.get(key) {
                    Some(event_val) if event_val == filter_val => continue,
                    _ => return false,
                }
            }
            true
        } else {
            event == filter
        }
    }
    
    /// Calculate next run time from cron expression
    fn calculate_next_run(&self, _cron: &str) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
        // In production, use cron parser library
        // For now, return current time + 1 minute
        Ok(chrono::Utc::now() + chrono::Duration::minutes(1))
    }
}

#[derive(sqlx::FromRow)]
struct WorkflowScheduleRow {
    id: String,
    tenant_id: String,
    name: String,
    version: String,
    description: Option<String>,
    definition: Value,
    triggers: Value,
    variables: Value,
    settings: Value,
    next_run_at: chrono::DateTime<chrono::Utc>,
}

// Migration for trigger logs and schedules (add to migrations file)
/*
CREATE TABLE IF NOT EXISTS workflow_trigger_logs (
    id VARCHAR(36) PRIMARY KEY,
    workflow_id VARCHAR(36) NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    trigger_type VARCHAR(50) NOT NULL,
    event_data JSONB,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflow_schedules (
    workflow_id VARCHAR(36) PRIMARY KEY REFERENCES workflows(id) ON DELETE CASCADE,
    cron VARCHAR(100) NOT NULL,
    next_run_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
*/
