//! WASM module execution backend

use super::{FunctionCall, FunctionResult};
use crate::error::AppError;
use tracing::info;

pub struct WasmExecutor;

impl WasmExecutor {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn run(&self, _module_path: &str, _call: &FunctionCall) -> Result<FunctionResult, AppError> {
        info!("WASM execution not yet implemented");
        
        Ok(FunctionResult {
            success: true,
            output: serde_json::json!({"message": "WASM execution placeholder"}),
            logs: vec![],
            execution_time_ms: 0,
            cold_start: false,
        })
    }
}
