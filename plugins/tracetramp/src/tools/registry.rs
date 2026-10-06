//! Tool Registry - Database and in-memory tool storage

use super::{Tool, ToolType};
use crate::error::AppError;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, error};

pub struct ToolRegistry {
    tools: Arc<RwLock<HashMap<String, Tool>>>,
    pool: PgPool,
}

impl ToolRegistry {
    pub fn new(pool: PgPool) -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            pool,
        }
    }
    
    /// Initialize and load tools from database
    pub async fn init(&self) -> Result<(), AppError> {
        let rows = sqlx::query_as::<_, ToolRow>(
            "SELECT id, name, description, tool_type, definition FROM tools WHERE is_active = true"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        let mut tools = self.tools.write().await;
        for row in rows {
            if let Ok(tool) = serde_json::from_value::<Tool>(row.definition) {
                tools.insert(tool.name.clone(), tool);
            } else {
                debug!(
                    "Skipping tool {} due to invalid definition payload",
                    row.name
                );
            }
        }
        
        info!("Loaded {} tools from database", tools.len());
        Ok(())
    }
    
    /// Get a tool by name
    pub async fn get(&self, name: &str) -> Option<Tool> {
        let tools = self.tools.read().await;
        tools.get(name).cloned()
    }
    
    /// List all tools
    pub async fn list(&self) -> Vec<Tool> {
        let tools = self.tools.read().await;
        tools.values().cloned().collect()
    }
    
    /// List tools by type
    pub async fn list_by_type(&self, tool_type: ToolType) -> Vec<Tool> {
        let tools = self.tools.read().await;
        tools.values()
            .filter(|t| std::mem::discriminant(&t.tool_type) == std::mem::discriminant(&tool_type))
            .cloned()
            .collect()
    }
    
    /// Register a new tool
    pub async fn register(&self, tool: Tool) -> Result<(), AppError> {
        let definition = serde_json::to_value(&tool)?;
        let tool_type_str = format!("{:?}", tool.tool_type).to_lowercase();
        
        sqlx::query(
            r#"
            INSERT INTO tools (id, name, description, tool_type, definition, is_active)
            VALUES ($1, $2, $3, $4, $5, true)
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                tool_type = EXCLUDED.tool_type,
                definition = EXCLUDED.definition,
                updated_at = NOW()
            "#
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&tool.name)
        .bind(&tool.description)
        .bind(&tool_type_str)
        .bind(&definition)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        
        let tool_name = tool.name.clone();
        let mut tools = self.tools.write().await;
        tools.insert(tool_name.clone(), tool);
        
        info!("Registered tool: {}", tool_name);
        Ok(())
    }
    
    /// Delete a tool
    pub async fn delete(&self, name: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM tools WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        
        let mut tools = self.tools.write().await;
        tools.remove(name);
        
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct ToolRow {
    id: String,
    name: String,
    description: Option<String>,
    tool_type: String,
    definition: serde_json::Value,
}
