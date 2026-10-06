//! Pipeline tool definitions
//!
//! Tools for orchestrating multi-step workflows

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineTool {
    pub name: String,
    pub steps: Vec<String>,
    pub parallel: bool,
}
