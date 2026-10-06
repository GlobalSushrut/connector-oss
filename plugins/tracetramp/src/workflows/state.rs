//! Workflow State Management
//!
//! Handles persistence, checkpoints, and recovery for workflow execution

use super::{WorkflowRun, RunStatus, StepResult, Workflow};
use crate::error::AppError;
use sqlx::PgPool;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{info, debug, error};
use chrono::Utc;

/// State manager for workflow persistence
pub struct StateManager {
    pool: PgPool,
}

impl StateManager {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Create a new workflow run record
    pub async fn create_run(&self, run: &WorkflowRun) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO workflow_runs (id, workflow_id, tenant_id, status, input, output, 
                                       step_results, current_step, started_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            "#
        )
        .bind(&run.id)
        .bind(&run.workflow_id)
        .bind(&run.tenant_id)
        .bind(&format!("{:?}", run.status).to_lowercase())
        .bind(&run.input)
        .bind(&run.output)
        .bind(&serde_json::to_value(&run.step_results).unwrap_or(Value::Null))
        .bind(&run.current_step)
        .bind(&run.started_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        info!("Created workflow run: {}", run.id);
        Ok(())
    }
    
    /// Get workflow run by ID
    pub async fn get_run(&self, run_id: &str) -> Result<Option<WorkflowRun>, AppError> {
        let row = sqlx::query_as::<_, WorkflowRunRow>(
            r#"
            SELECT id, workflow_id, tenant_id, status, input, output,
                   step_results, current_step, started_at, completed_at, error
            FROM workflow_runs WHERE id = $1
            "#
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        match row {
            Some(r) => {
                let step_results: HashMap<String, StepResult> = 
                    serde_json::from_value(r.step_results).unwrap_or_default();
                
                Ok(Some(WorkflowRun {
                    id: r.id,
                    workflow_id: r.workflow_id,
                    tenant_id: r.tenant_id,
                    status: parse_run_status(&r.status),
                    input: r.input,
                    output: r.output,
                    step_results,
                    current_step: r.current_step,
                    started_at: r.started_at,
                    completed_at: r.completed_at,
                    error: r.error,
                }))
            }
            None => Ok(None),
        }
    }
    
    /// Update run status
    pub async fn update_status(&self, run_id: &str, status: RunStatus) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE workflow_runs SET status = $2 WHERE id = $1"
        )
        .bind(run_id)
        .bind(&format!("{:?}", status).to_lowercase())
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        debug!("Updated run {} status to {:?}", run_id, status);
        Ok(())
    }
    
    /// Save step result
    pub async fn save_step_result(
        &self,
        run_id: &str,
        step_id: &str,
        result: &StepResult,
    ) -> Result<(), AppError> {
        // Get current step results
        let run = self.get_run(run_id).await?;
        
        if let Some(mut run) = run {
            run.step_results.insert(step_id.to_string(), result.clone());
            run.current_step = Some(step_id.to_string());
            
            sqlx::query(
                "UPDATE workflow_runs SET step_results = $2, current_step = $3 WHERE id = $1"
            )
            .bind(run_id)
            .bind(&serde_json::to_value(&run.step_results).unwrap_or(Value::Null))
            .bind(&run.current_step)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }
        
        Ok(())
    }
    
    /// Create checkpoint for recovery
    pub async fn checkpoint(&self, run_id: &str, state: &Value) -> Result<String, AppError> {
        let checkpoint_id = uuid::Uuid::new_v4().to_string();
        
        sqlx::query(
            r#"
            INSERT INTO workflow_checkpoints (id, run_id, state, created_at)
            VALUES ($1, $2, $3, NOW())
            "#
        )
        .bind(&checkpoint_id)
        .bind(run_id)
        .bind(state)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        info!("Created checkpoint {} for run {}", checkpoint_id, run_id);
        Ok(checkpoint_id)
    }
    
    /// Get latest checkpoint for recovery
    pub async fn get_latest_checkpoint(&self, run_id: &str) -> Result<Option<Value>, AppError> {
        let row = sqlx::query_as::<_, CheckpointRow>(
            r#"
            SELECT state FROM workflow_checkpoints 
            WHERE run_id = $1 
            ORDER BY created_at DESC 
            LIMIT 1
            "#
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        Ok(row.map(|r| r.state))
    }
    
    /// Complete workflow run
    pub async fn complete_run(
        &self,
        run_id: &str,
        output: Option<Value>,
        error: Option<String>,
    ) -> Result<(), AppError> {
        let status = if error.is_some() { 
            RunStatus::Failed 
        } else { 
            RunStatus::Completed 
        };
        
        sqlx::query(
            r#"
            UPDATE workflow_runs 
            SET status = $2, output = $3, error = $4, completed_at = NOW()
            WHERE id = $1
            "#
        )
        .bind(run_id)
        .bind(&format!("{:?}", status).to_lowercase())
        .bind(&output)
        .bind(&error)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        info!("Completed workflow run: {} (status: {:?})", run_id, status);
        Ok(())
    }
    
    /// List runs for a workflow
    pub async fn list_runs(
        &self,
        workflow_id: &str,
        limit: i64,
    ) -> Result<Vec<WorkflowRun>, AppError> {
        let rows = sqlx::query_as::<_, WorkflowRunRow>(
            r#"
            SELECT id, workflow_id, tenant_id, status, input, output,
                   step_results, current_step, started_at, completed_at, error
            FROM workflow_runs 
            WHERE workflow_id = $1
            ORDER BY started_at DESC
            LIMIT $2
            "#
        )
        .bind(workflow_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        let mut runs = Vec::new();
        for r in rows {
            let step_results: HashMap<String, StepResult> = 
                serde_json::from_value(r.step_results).unwrap_or_default();
            
            runs.push(WorkflowRun {
                id: r.id,
                workflow_id: r.workflow_id,
                tenant_id: r.tenant_id,
                status: parse_run_status(&r.status),
                input: r.input,
                output: r.output,
                step_results,
                current_step: r.current_step,
                started_at: r.started_at,
                completed_at: r.completed_at,
                error: r.error,
            });
        }
        
        Ok(runs)
    }
}

// Database row types
#[derive(sqlx::FromRow)]
struct WorkflowRunRow {
    id: String,
    workflow_id: String,
    tenant_id: String,
    status: String,
    input: Value,
    output: Option<Value>,
    step_results: Value,
    current_step: Option<String>,
    started_at: chrono::DateTime<Utc>,
    completed_at: Option<chrono::DateTime<Utc>>,
    error: Option<String>,
}

#[derive(sqlx::FromRow)]
struct CheckpointRow {
    state: Value,
}

fn parse_run_status(status: &str) -> RunStatus {
    match status {
        "running" => RunStatus::Running,
        "completed" => RunStatus::Completed,
        "failed" => RunStatus::Failed,
        "cancelled" => RunStatus::Cancelled,
        "waiting_human" => RunStatus::WaitingHuman,
        "paused" => RunStatus::Paused,
        _ => RunStatus::Pending,
    }
}
