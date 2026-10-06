//! Function execution backends
//!
//! Supports: OpenFaaS, AWS Lambda, Docker containers, WASM, local processes

pub mod openfaas;
pub mod lambda;
pub mod docker;
pub mod wasm;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub function_name: String,
    pub parameters: serde_json::Value,
    pub timeout_seconds: u64,
    pub async_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionResult {
    pub success: bool,
    pub output: serde_json::Value,
    pub logs: Vec<String>,
    pub execution_time_ms: u64,
    pub cold_start: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionConfig {
    pub name: String,
    pub backend: FunctionBackend,
    pub runtime: String,
    pub memory_mb: u64,
    pub timeout_seconds: u64,
    pub env_vars: HashMap<String, String>,
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionBackend {
    OpenFaas { gateway_url: String },
    Lambda { region: String, role_arn: String },
    Docker { image: String, network: String },
    Wasm { module_path: String },
    Local { command: String },
}
