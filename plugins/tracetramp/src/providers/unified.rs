//! Unified provider router - intelligently routes requests to appropriate backend
//!
//! Handles model aliasing, fallbacks, load balancing, and cost optimization

use super::{Provider, UnifiedRequest, UnifiedResponse, StreamChunk, TokenUsage, ProviderConfig};
use crate::error::AppError;
use std::collections::HashMap;
use tracing::{info, debug, warn};

/// Smart router for LLM requests
pub struct UnifiedRouter {
    providers: HashMap<String, Box<dyn Provider>>,
    routing_rules: Vec<RoutingRule>,
    fallback_chain: Vec<String>,
}

#[derive(Debug, Clone)]
struct RoutingRule {
    condition: RoutingCondition,
    target_provider: String,
    priority: u32,
}

#[derive(Debug, Clone)]
enum RoutingCondition {
    ModelPrefix(String),
    CostUnder(f64),
    LatencyRequirement(u64), // max ms
    ToolRequired,
    StreamingRequired,
    Tenant(String),
    Intent(String),
}

impl UnifiedRouter {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            routing_rules: vec![],
            fallback_chain: vec![],
        }
    }
    
    pub fn register_provider(&mut self, name: String, provider: Box<dyn Provider>) {
        self.providers.insert(name, provider);
    }
    
    pub fn add_routing_rule(&mut self, condition: RoutingCondition, target: String, priority: u32) {
        self.routing_rules.push(RoutingRule {
            condition,
            target_provider: target,
            priority,
        });
        // Sort by priority (higher first)
        self.routing_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    
    /// Route request to best provider
    pub async fn route(&self, request: &UnifiedRequest) -> Result<&dyn Provider, AppError> {
        // First check explicit model routing
        for rule in &self.routing_rules {
            if self.matches_condition(&rule.condition, request) {
                if let Some(provider) = self.providers.get(&rule.target_provider) {
                    debug!("Routing to {} based on {:?}", rule.target_provider, rule.condition);
                    return Ok(provider.as_ref());
                }
            }
        }
        
        // Default routing by model name pattern
        let provider = self.route_by_model(&request.model)?;
        Ok(provider)
    }
    
    fn matches_condition(&self, condition: &RoutingCondition, request: &UnifiedRequest) -> bool {
        match condition {
            RoutingCondition::ModelPrefix(prefix) => request.model.starts_with(prefix),
            RoutingCondition::StreamingRequired => request.stream,
            RoutingCondition::ToolRequired => request.tools.is_some(),
            RoutingCondition::Tenant(_) => true, // Would check tenant context
            RoutingCondition::CostUnder(_) => true, // Would check budget
            RoutingCondition::LatencyRequirement(_) => true, // Would check SLA
            RoutingCondition::Intent(_) => true, // Would check intent classification
        }
    }
    
    fn route_by_model(&self, model: &str) -> Result<&dyn Provider, AppError> {
        // Provider-specific prefixes
        let provider_name = if model.starts_with("gpt-") || model.starts_with("o1") {
            "openai"
        } else if model.starts_with("claude-") {
            "anthropic"
        } else if model.starts_with("llama-") || model.starts_with("mistral-") || model.starts_with("qwen-") {
            "ollama"
        } else if model.contains("azure") {
            "azure"
        } else if model.starts_with("mistral/") {
            "mistral"
        } else {
            // Default fallback
            "openai"
        };
        
        self.providers.get(provider_name)
            .map(|p| p.as_ref())
            .ok_or_else(|| AppError::NotFound(format!("Provider for model {} not found", model)))
    }
    
    /// Execute with fallback chain
    pub async fn execute_with_fallback(
        &self,
        mut request: UnifiedRequest,
    ) -> Result<UnifiedResponse, AppError> {
        let mut last_error = None;
        
        for provider_name in &self.fallback_chain {
            if let Some(provider) = self.providers.get(provider_name) {
                match provider.complete(request.clone()).await {
                    Ok(response) => return Ok(response),
                    Err(e) => {
                        warn!("Provider {} failed: {}, trying fallback", provider_name, e);
                        last_error = Some(e);
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| AppError::Internal("All providers failed".to_string())))
    }
}

/// Model alias resolution
pub struct ModelAliases {
    aliases: HashMap<String, String>,
}

impl ModelAliases {
    pub fn new() -> Self {
        let mut aliases = HashMap::new();
        
        // Standard aliases
        aliases.insert("smart".to_string(), "gpt-4o".to_string());
        aliases.insert("fast".to_string(), "gpt-4o-mini".to_string());
        aliases.insert("coding".to_string(), "claude-3-5-sonnet-20241022".to_string());
        aliases.insert("local".to_string(), "llama3.2:latest".to_string());
        aliases.insert("vision".to_string(), "gpt-4o".to_string());
        aliases.insert("cheap".to_string(), "gpt-4o-mini".to_string());
        
        Self { aliases }
    }
    
    pub fn resolve(&self, alias: &str) -> String {
        self.aliases.get(alias).cloned().unwrap_or_else(|| alias.to_string())
    }
    
    pub fn register(&mut self, alias: String, model: String) {
        self.aliases.insert(alias, model);
    }
}

/// Cost optimizer - picks cheapest provider for given quality level
pub struct CostOptimizer {
    pricing: HashMap<String, ModelPricing>,
}

#[derive(Debug, Clone)]
struct ModelPricing {
    input_per_1k: f64,
    output_per_1k: f64,
    quality_score: f64, // 0-1
    latency_ms: u64,
}

impl CostOptimizer {
    pub fn new() -> Self {
        let mut pricing = HashMap::new();
        
        // Pricing data (kept current with market rates)
        pricing.insert("gpt-4o".to_string(), ModelPricing {
            input_per_1k: 0.0025,
            output_per_1k: 0.01,
            quality_score: 0.95,
            latency_ms: 800,
        });
        
        pricing.insert("gpt-4o-mini".to_string(), ModelPricing {
            input_per_1k: 0.00015,
            output_per_1k: 0.0006,
            quality_score: 0.85,
            latency_ms: 400,
        });
        
        pricing.insert("claude-3-5-sonnet".to_string(), ModelPricing {
            input_per_1k: 0.003,
            output_per_1k: 0.015,
            quality_score: 0.94,
            latency_ms: 900,
        });
        
        pricing.insert("llama3.2:latest".to_string(), ModelPricing {
            input_per_1k: 0.0, // Local = free
            output_per_1k: 0.0,
            quality_score: 0.75,
            latency_ms: 1200,
        });
        
        Self { pricing }
    }
    
    /// Find cheapest model meeting quality threshold
    pub fn find_cost_effective(&self, min_quality: f64, expected_tokens: u64) -> Option<String> {
        self.pricing
            .iter()
            .filter(|(_, p)| p.quality_score >= min_quality)
            .min_by(|a, b| {
                let cost_a = (a.1.input_per_1k + a.1.output_per_1k) * (expected_tokens as f64 / 1000.0);
                let cost_b = (b.1.input_per_1k + b.1.output_per_1k) * (expected_tokens as f64 / 1000.0);
                cost_a.partial_cmp(&cost_b).unwrap()
            })
            .map(|(name, _)| name.clone())
    }
}
