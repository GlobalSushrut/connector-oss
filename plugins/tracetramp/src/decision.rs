//! Decision Tree Recording - The True Moat
//!
//! Captures raw LLM decision-making process with complete prompt/response evidence

use crate::types::{DecisionTree, DecisionNode, DecisionNodeType, DecisionMetadata, PolicyCheck};
use crate::providers::TokenUsage;
use crate::error::AppError;
use chrono::Utc;
use sqlx::PgPool;
use tracing::{info, debug};

/// Builder for constructing decision trees
pub struct DecisionTreeBuilder {
    trace_id: String,
    request_id: String,
    tenant_id: String,
    actor_id: String,
    app_id: String,
    session_id: Option<String>,
    workflow_id: Option<String>,
    root: Option<DecisionNode>,
    current_node_id: usize,
    nodes: Vec<DecisionNode>,
}

impl DecisionTreeBuilder {
    pub fn new(
        trace_id: &str,
        request_id: &str,
        tenant_id: &str,
        actor_id: &str,
        app_id: &str,
    ) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            request_id: request_id.to_string(),
            tenant_id: tenant_id.to_string(),
            actor_id: actor_id.to_string(),
            app_id: app_id.to_string(),
            session_id: None,
            workflow_id: None,
            root: None,
            current_node_id: 0,
            nodes: vec![],
        }
    }
    
    pub fn with_session(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }
    
    pub fn with_workflow(mut self, workflow_id: &str) -> Self {
        self.workflow_id = Some(workflow_id.to_string());
        self
    }
    
    /// Add a root decision node (the primary LLM call)
    pub fn add_root_decision(
        &mut self,
        node_type: DecisionNodeType,
        input: &str,
        context: Option<&str>,
        output: &str,
        action: &str,
        model: &str,
        provider: &str,
        tokens: TokenUsage,
        latency_ms: u64,
    ) -> String {
        let node_id = format!("node-{}", self.current_node_id);
        self.current_node_id += 1;
        
        let total_tokens = tokens.total_tokens;
        let node = DecisionNode {
            node_id: node_id.clone(),
            node_type,
            input: input.to_string(),
            context: context.map(|s| s.to_string()),
            output: output.to_string(),
            action: action.to_string(),
            model: model.to_string(),
            provider: provider.to_string(),
            tokens,
            latency_ms,
            children: vec![],
            confidence: None,
            policy_checks: vec![],
        };
        
        self.root = Some(node);
        self.nodes.push(self.root.clone().unwrap());
        
        info!("Recorded root decision: {} (model: {}, tokens: {})", 
            node_id, model, total_tokens);
        
        node_id
    }
    
    /// Add a child decision to a parent node
    pub fn add_child_decision(
        &mut self,
        parent_id: &str,
        node_type: DecisionNodeType,
        input: &str,
        context: Option<&str>,
        output: &str,
        action: &str,
        model: &str,
        provider: &str,
        tokens: TokenUsage,
        latency_ms: u64,
    ) -> String {
        let node_id = format!("node-{}", self.current_node_id);
        self.current_node_id += 1;
        
        let node = DecisionNode {
            node_id: node_id.clone(),
            node_type,
            input: input.to_string(),
            context: context.map(|s| s.to_string()),
            output: output.to_string(),
            action: action.to_string(),
            model: model.to_string(),
            provider: provider.to_string(),
            tokens,
            latency_ms,
            children: vec![],
            confidence: None,
            policy_checks: vec![],
        };
        
        // Find parent and add child (simplified - in production use proper tree structure)
        if let Some(ref mut root) = self.root {
            if root.node_id == parent_id {
                root.children.push(node.clone());
            }
        }
        
        self.nodes.push(node);
        
        debug!("Recorded child decision: {} under parent: {}", node_id, parent_id);
        
        node_id
    }
    
    /// Add policy check to a decision node
    pub fn add_policy_check(&mut self, node_id: &str, check: PolicyCheck) {
        if let Some(ref mut root) = self.root {
            if root.node_id == node_id {
                root.policy_checks.push(check);
            }
        }
    }
    
    /// Build the final decision tree
    pub fn build(self) -> DecisionTree {
        let total_tokens: u64 = self.nodes.iter().map(|n| n.tokens.total_tokens).sum();
        let total_cost: f64 = self.nodes.iter().map(|n| n.tokens.estimated_cost_usd).sum();
        let total_latency: u64 = self.nodes.iter().map(|n| n.latency_ms).sum();
        
        let final_outcome = self.root.as_ref()
            .map(|r| r.action.clone())
            .unwrap_or_else(|| "unknown".to_string());
        
        DecisionTree {
            trace_id: self.trace_id,
            request_id: self.request_id,
            timestamp: Utc::now(),
            root: self.root.unwrap_or_else(|| DecisionNode {
                node_id: "empty".to_string(),
                node_type: DecisionNodeType::IntentRecognition,
                input: String::new(),
                context: None,
                output: String::new(),
                action: "no_decision".to_string(),
                model: "none".to_string(),
                provider: "none".to_string(),
                tokens: TokenUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    total_tokens: 0,
                    estimated_cost_usd: 0.0,
                },
                latency_ms: 0,
                children: vec![],
                confidence: None,
                policy_checks: vec![],
            }),
            metadata: DecisionMetadata {
                tenant_id: self.tenant_id,
                actor_id: self.actor_id,
                app_id: self.app_id,
                session_id: self.session_id,
                workflow_id: self.workflow_id,
                total_tokens,
                total_cost_usd: total_cost,
                total_latency_ms: total_latency,
                node_count: self.nodes.len(),
                final_outcome,
            },
        }
    }
}

/// Format decision tree as a readable tree structure
pub fn format_decision_tree(tree: &DecisionTree) -> String {
    let mut output = String::new();
    output.push_str(&format!("=== DECISION TREE ===\n"));
    output.push_str(&format!("Trace ID: {}\n", tree.trace_id));
    output.push_str(&format!("Request ID: {}\n", tree.request_id));
    output.push_str(&format!("Timestamp: {}\n", tree.timestamp));
    output.push_str(&format!("Total Nodes: {}\n", tree.metadata.node_count));
    let total_cost_str = format!("{:.4}", tree.metadata.total_cost_usd);
    output.push_str(&format!("Total Cost: ${}\n", total_cost_str));
    output.push_str(&format!("Final Outcome: {}\n", tree.metadata.final_outcome));
    output.push_str("\n");
    
    format_node(&tree.root, &mut output, 0);
    
    output
}

fn format_node(node: &DecisionNode, output: &mut String, depth: usize) {
    let indent = "  ".repeat(depth);
    let branch = if depth == 0 { "└──" } else { "├──" };
    
    output.push_str(&format!("\n{} {} [{}] {} ({} / {})\n", 
        indent, branch, node.node_id, 
        format!("{:?}", node.node_type).to_lowercase(),
        node.model, node.provider));
    
    // Input (the raw prompt - the true evidence)
    output.push_str(&format!("{}    INPUT (raw prompt):\n", indent));
    let input_preview = if node.input.len() > 200 {
        format!("{}... [{} more chars]", &node.input[..200], node.input.len() - 200)
    } else {
        node.input.clone()
    };
    for line in input_preview.lines() {
        output.push_str(&format!("{}      {}\n", indent, line));
    }
    
    // Context if present
    if let Some(ref ctx) = node.context {
        output.push_str(&format!("{}    CONTEXT (system prompt):\n", indent));
        let ctx_preview = if ctx.len() > 100 {
            format!("{}... [{} more chars]", &ctx[..100], ctx.len() - 100)
        } else {
            ctx.clone()
        };
        output.push_str(&format!("{}      {}\n", indent, ctx_preview));
    }
    
    // Output (LLM response)
    output.push_str(&format!("{}    OUTPUT (LLM response):\n", indent));
    let output_preview = if node.output.len() > 200 {
        format!("{}... [{} more chars]", &node.output[..200], node.output.len() - 200)
    } else {
        node.output.clone()
    };
    for line in output_preview.lines() {
        output.push_str(&format!("{}      {}\n", indent, line));
    }
    
    // Action (derived decision)
    output.push_str(&format!("{}    ACTION (decision): {}\n", indent, node.action));
    
    // Technical details
    let cost_str = format!("{:.4}", node.tokens.estimated_cost_usd);
    output.push_str(&format!("{}    TOKENS: {} in / {} out / {} total | COST: ${} | LATENCY: {}ms\n",
        indent, node.tokens.input_tokens, node.tokens.output_tokens, 
        node.tokens.total_tokens, cost_str, node.latency_ms));
    
    // Policy checks
    if !node.policy_checks.is_empty() {
        output.push_str(&format!("{}    POLICY CHECKS:\n", indent));
        for check in &node.policy_checks {
            output.push_str(&format!("{}      - {}: {:?}\n", 
                indent, check.policy_name, check.result));
        }
    }
    
    // Children
    for (i, child) in node.children.iter().enumerate() {
        let is_last = i == node.children.len() - 1;
        let child_branch = if is_last { "└──" } else { "├──" };
        output.push_str(&format!("{}    {} CHILD DECISION:\n", indent, child_branch));
        format_node(child, output, depth + 2);
    }
}

/// Serialize decision tree to JSON for storage/evidence
pub fn tree_to_json(tree: &DecisionTree) -> Result<serde_json::Value, AppError> {
    serde_json::to_value(tree)
        .map_err(|e| AppError::Serialization(e.to_string()))
}

pub async fn persist_decision_tree(
    pool: &PgPool,
    tree: &DecisionTree,
) -> Result<(), AppError> {
    let tree_data = tree_to_json(tree)?;
    sqlx::query(
        "INSERT INTO decision_trees (trace_id, request_id, tenant_id, tree_data, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW())
         ON CONFLICT (trace_id) DO UPDATE SET
            request_id = EXCLUDED.request_id,
            tenant_id = EXCLUDED.tenant_id,
            tree_data = EXCLUDED.tree_data,
            updated_at = NOW()"
    )
    .bind(&tree.trace_id)
    .bind(&tree.request_id)
    .bind(&tree.metadata.tenant_id)
    .bind(tree_data)
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

