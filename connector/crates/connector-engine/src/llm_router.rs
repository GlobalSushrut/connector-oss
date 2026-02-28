//! # LLM Router — Retry, Fallback, Circuit Breaker, Cost Tracking
//!
//! Wraps `LlmClient` with production-grade resilience:
//! 1. **Retry**: Exponential backoff with jitter on transient failures
//! 2. **Fallback**: Ordered list of providers — if primary fails, try next
//! 3. **Circuit Breaker**: Trip after N consecutive failures, half-open after cooldown
//! 4. **Cost Tracking**: Per-provider token counts and estimated cost
//!
//! Source: CHECKLIST Phase 3, KERNEL_SCALABILITY_ARCH §6.5

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::llm::{LlmConfig, LlmClient, LlmResponse, LlmError, ChatMessage};

// ── Retry Config ────────────────────────────────────────────

/// Retry configuration for transient failures.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries)
    pub max_retries: u32,
    /// Base delay between retries (doubles each attempt)
    pub base_delay_ms: u64,
    /// Maximum delay cap
    pub max_delay_ms: u64,
    /// HTTP status codes considered retryable
    pub retryable_statuses: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 500,
            max_delay_ms: 10_000,
            retryable_statuses: vec![429, 500, 502, 503, 504],
        }
    }
}

// ── Circuit Breaker ─────────────────────────────────────────

/// Circuit breaker state.
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the circuit
    pub failure_threshold: u32,
    /// Cooldown before transitioning to half-open
    pub cooldown: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown: Duration::from_secs(30),
        }
    }
}

/// Per-provider circuit breaker state.
#[derive(Debug, Clone)]
struct ProviderCircuit {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure: Option<Instant>,
    config: CircuitBreakerConfig,
}

impl ProviderCircuit {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure: None,
            config,
        }
    }

    fn is_available(&self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                // Check if cooldown has elapsed
                if let Some(last) = self.last_failure {
                    last.elapsed() >= self.config.cooldown
                } else {
                    true
                }
            }
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = CircuitState::Closed;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());
        if self.consecutive_failures >= self.config.failure_threshold {
            self.state = CircuitState::Open;
        }
    }
}

// ── Cost Tracking ───────────────────────────────────────────

/// Per-provider cost tracking.
#[derive(Debug, Clone, Default)]
pub struct ProviderCost {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_requests: u64,
    pub total_failures: u64,
    pub estimated_cost_usd: f64,
}

/// Cost rates per 1M tokens (input, output) in USD.
fn cost_per_million(provider: &str, model: &str) -> (f64, f64) {
    match (provider, model) {
        ("openai", m) if m.contains("gpt-4o-mini") => (0.15, 0.60),
        ("openai", m) if m.contains("gpt-4o") => (2.50, 10.00),
        ("openai", m) if m.contains("gpt-4") => (30.00, 60.00),
        ("openai", m) if m.contains("o1") => (15.00, 60.00),
        ("openai", m) if m.contains("o3") => (10.00, 40.00),
        ("anthropic", m) if m.contains("haiku") => (0.25, 1.25),
        ("anthropic", m) if m.contains("sonnet") => (3.00, 15.00),
        ("anthropic", m) if m.contains("opus") => (15.00, 75.00),
        ("gemini", m) if m.contains("flash") => (0.075, 0.30),
        ("gemini", m) if m.contains("pro") => (1.25, 5.00),
        ("deepseek", _) => (0.14, 0.28),
        ("groq", _) => (0.05, 0.08),
        ("together", _) => (0.20, 0.60),
        ("mistral", _) => (0.25, 0.25),
        _ => (1.00, 3.00), // Conservative default
    }
}

// ── Router ──────────────────────────────────────────────────

/// Router configuration.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub retry: RetryConfig,
    pub circuit_breaker: CircuitBreakerConfig,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

/// LLM Router — resilient multi-provider LLM access.
///
/// Wraps `LlmClient` with retry, fallback, circuit breaker, and cost tracking.
pub struct LlmRouter {
    client: LlmClient,
    /// Ordered list of LLM configs (primary first, then fallbacks)
    providers: Vec<LlmConfig>,
    config: RouterConfig,
    /// Per-provider circuit breakers (keyed by "provider:model")
    circuits: Arc<Mutex<HashMap<String, ProviderCircuit>>>,
    /// Per-provider cost tracking
    costs: Arc<Mutex<HashMap<String, ProviderCost>>>,
}

impl LlmRouter {
    /// Create a router with a single provider (no fallback).
    pub fn new(primary: LlmConfig) -> Self {
        Self::with_fallbacks(vec![primary], RouterConfig::default())
    }

    /// Create a router with ordered fallback providers.
    pub fn with_fallbacks(providers: Vec<LlmConfig>, config: RouterConfig) -> Self {
        let mut circuits = HashMap::new();
        for p in &providers {
            let key = provider_key(p);
            circuits.insert(key, ProviderCircuit::new(config.circuit_breaker.clone()));
        }

        Self {
            client: LlmClient::new(),
            providers,
            config,
            circuits: Arc::new(Mutex::new(circuits)),
            costs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Send a chat completion with retry + fallback + circuit breaker.
    pub async fn chat(&self, messages: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        let mut last_error = None;

        for cfg in &self.providers {
            let key = provider_key(cfg);

            // Check circuit breaker
            {
                let mut circuits = self.circuits.lock().unwrap();
                let circuit = circuits.entry(key.clone())
                    .or_insert_with(|| ProviderCircuit::new(self.config.circuit_breaker.clone()));

                if !circuit.is_available() {
                    last_error = Some(LlmError {
                        message: format!("Circuit open for {}", key),
                        status: None,
                        provider: cfg.provider.clone(),
                    });
                    continue;
                }

                // Transition open → half-open if cooldown elapsed
                if circuit.state == CircuitState::Open {
                    circuit.state = CircuitState::HalfOpen;
                }
            }

            // Try with retries
            match self.chat_with_retry(cfg, messages.clone()).await {
                Ok(resp) => {
                    // Record success
                    if let Ok(mut circuits) = self.circuits.lock() {
                        if let Some(c) = circuits.get_mut(&key) {
                            c.record_success();
                        }
                    }
                    // Track cost
                    self.track_cost(&key, cfg, &resp);
                    return Ok(resp);
                }
                Err(e) => {
                    // Record failure
                    if let Ok(mut circuits) = self.circuits.lock() {
                        if let Some(c) = circuits.get_mut(&key) {
                            c.record_failure();
                        }
                    }
                    if let Ok(mut costs) = self.costs.lock() {
                        let cost = costs.entry(key.clone()).or_default();
                        cost.total_failures += 1;
                    }
                    last_error = Some(e);
                    // Continue to next fallback provider
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LlmError {
            message: "No providers configured".to_string(),
            status: None,
            provider: "router".to_string(),
        }))
    }

    /// Convenience: single message completion with retry + fallback.
    pub async fn complete(&self, input: &str, system: Option<&str>) -> Result<LlmResponse, LlmError> {
        let mut msgs = Vec::new();
        if let Some(s) = system {
            msgs.push(ChatMessage { role: "system".into(), content: s.into() });
        }
        msgs.push(ChatMessage { role: "user".into(), content: input.into() });
        self.chat(msgs).await
    }

    /// Synchronous completion (blocks current thread).
    pub fn complete_sync(&self, input: &str, system: Option<&str>) -> Result<LlmResponse, LlmError> {
        tokio::runtime::Runtime::new()
            .map_err(|e| LlmError { message: e.to_string(), status: None, provider: "router".to_string() })?
            .block_on(self.complete(input, system))
    }

    /// Synchronous chat with full message history (blocks current thread).
    ///
    /// Use this for multi-turn conversations where you need to pass
    /// system + history + user messages as a Vec<ChatMessage>.
    pub fn chat_sync(&self, messages: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        tokio::runtime::Runtime::new()
            .map_err(|e| LlmError { message: e.to_string(), status: None, provider: "router".to_string() })?
            .block_on(self.chat(messages))
    }

    /// Get cost summary for all providers.
    pub fn cost_summary(&self) -> HashMap<String, ProviderCost> {
        self.costs.lock().unwrap().clone()
    }

    /// Get total estimated cost across all providers.
    pub fn total_cost_usd(&self) -> f64 {
        self.costs.lock().unwrap().values().map(|c| c.estimated_cost_usd).sum()
    }

    /// Get circuit breaker states.
    pub fn circuit_states(&self) -> HashMap<String, CircuitState> {
        self.circuits.lock().unwrap().iter()
            .map(|(k, v)| (k.clone(), v.state.clone()))
            .collect()
    }

    /// Reset all circuit breakers.
    pub fn reset_circuits(&self) {
        let mut circuits = self.circuits.lock().unwrap();
        for c in circuits.values_mut() {
            c.state = CircuitState::Closed;
            c.consecutive_failures = 0;
            c.last_failure = None;
        }
    }

    // ── Internal ────────────────────────────────────────────

    async fn chat_with_retry(
        &self,
        cfg: &LlmConfig,
        messages: Vec<ChatMessage>,
    ) -> Result<LlmResponse, LlmError> {
        let mut last_error = None;

        for attempt in 0..=self.config.retry.max_retries {
            match self.client.chat(cfg, messages.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    let is_retryable = e.status
                        .map(|s| self.config.retry.retryable_statuses.contains(&s))
                        .unwrap_or(true); // Network errors are retryable

                    if !is_retryable || attempt == self.config.retry.max_retries {
                        return Err(e);
                    }

                    last_error = Some(e);

                    // Exponential backoff with jitter
                    let delay = std::cmp::min(
                        self.config.retry.base_delay_ms * 2u64.pow(attempt),
                        self.config.retry.max_delay_ms,
                    );
                    // Simple jitter: ±25%
                    let jitter = delay / 4;
                    let actual_delay = delay.saturating_sub(jitter / 2)
                        + (std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .subsec_nanos() as u64 % jitter.max(1));

                    tokio::time::sleep(Duration::from_millis(actual_delay)).await;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LlmError {
            message: "Retry exhausted".to_string(),
            status: None,
            provider: cfg.provider.clone(),
        }))
    }

    fn track_cost(&self, key: &str, cfg: &LlmConfig, resp: &LlmResponse) {
        let (input_rate, output_rate) = cost_per_million(&cfg.provider, &cfg.model);
        let input_cost = (resp.input_tokens as f64 / 1_000_000.0) * input_rate;
        let output_cost = (resp.output_tokens as f64 / 1_000_000.0) * output_rate;

        if let Ok(mut costs) = self.costs.lock() {
            let cost = costs.entry(key.to_string()).or_default();
            cost.total_input_tokens += resp.input_tokens as u64;
            cost.total_output_tokens += resp.output_tokens as u64;
            cost.total_requests += 1;
            cost.estimated_cost_usd += input_cost + output_cost;
        }
    }
}

fn provider_key(cfg: &LlmConfig) -> String {
    format!("{}:{}", cfg.provider, cfg.model)
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_trips_after_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            cooldown: Duration::from_secs(30),
        };
        let mut circuit = ProviderCircuit::new(config);

        assert!(circuit.is_available());
        assert_eq!(circuit.state, CircuitState::Closed);

        // 2 failures — still closed
        circuit.record_failure();
        circuit.record_failure();
        assert_eq!(circuit.state, CircuitState::Closed);
        assert!(circuit.is_available());

        // 3rd failure — trips to open
        circuit.record_failure();
        assert_eq!(circuit.state, CircuitState::Open);
        assert!(!circuit.is_available()); // cooldown not elapsed

        // Success resets
        circuit.record_success();
        assert_eq!(circuit.state, CircuitState::Closed);
        assert_eq!(circuit.consecutive_failures, 0);
    }

    #[test]
    fn test_circuit_breaker_cooldown() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_millis(10),
        };
        let mut circuit = ProviderCircuit::new(config);

        circuit.record_failure();
        assert_eq!(circuit.state, CircuitState::Open);
        assert!(!circuit.is_available());

        // Wait for cooldown
        std::thread::sleep(Duration::from_millis(15));
        assert!(circuit.is_available()); // cooldown elapsed → available
    }

    #[test]
    fn test_cost_tracking() {
        let cfg = LlmConfig::new("openai", "gpt-4o", "sk-test");
        let router = LlmRouter::new(cfg);

        // Simulate cost tracking
        let resp = LlmResponse {
            text: "Hello".to_string(),
            model: "gpt-4o".to_string(),
            provider: "openai".to_string(),
            input_tokens: 100,
            output_tokens: 50,
            finish_reason: "stop".to_string(),
        };

        let key = "openai:gpt-4o";
        let cfg = &router.providers[0];
        router.track_cost(key, cfg, &resp);

        let costs = router.cost_summary();
        let cost = costs.get(key).unwrap();
        assert_eq!(cost.total_input_tokens, 100);
        assert_eq!(cost.total_output_tokens, 50);
        assert_eq!(cost.total_requests, 1);
        assert!(cost.estimated_cost_usd > 0.0);

        // gpt-4o: $2.50/1M input, $10.00/1M output
        let expected = (100.0 / 1_000_000.0) * 2.50 + (50.0 / 1_000_000.0) * 10.00;
        assert!((cost.estimated_cost_usd - expected).abs() < 1e-10,
            "Cost should be ~{}, got {}", expected, cost.estimated_cost_usd);
    }

    #[test]
    fn test_cost_per_million_rates() {
        // Verify key pricing
        assert_eq!(cost_per_million("openai", "gpt-4o"), (2.50, 10.00));
        assert_eq!(cost_per_million("openai", "gpt-4o-mini"), (0.15, 0.60));
        assert_eq!(cost_per_million("anthropic", "claude-3.5-sonnet"), (3.00, 15.00));
        assert_eq!(cost_per_million("anthropic", "claude-3-haiku"), (0.25, 1.25));
        assert_eq!(cost_per_million("gemini", "gemini-2.0-flash"), (0.075, 0.30));
        assert_eq!(cost_per_million("deepseek", "deepseek-chat"), (0.14, 0.28));
    }

    #[test]
    fn test_router_creation_with_fallbacks() {
        let primary = LlmConfig::new("openai", "gpt-4o", "sk-test");
        let fallback1 = LlmConfig::new("anthropic", "claude-3.5-sonnet", "sk-ant");
        let fallback2 = LlmConfig::new("deepseek", "deepseek-chat", "sk-ds");

        let router = LlmRouter::with_fallbacks(
            vec![primary, fallback1, fallback2],
            RouterConfig::default(),
        );

        assert_eq!(router.providers.len(), 3);

        let states = router.circuit_states();
        assert_eq!(states.len(), 3);
        assert!(states.values().all(|s| *s == CircuitState::Closed));
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.base_delay_ms, 500);
        assert!(config.retryable_statuses.contains(&429));
        assert!(config.retryable_statuses.contains(&503));
    }

    #[test]
    fn test_provider_key() {
        let cfg = LlmConfig::new("openai", "gpt-4o", "sk-test");
        assert_eq!(provider_key(&cfg), "openai:gpt-4o");
    }

    #[test]
    fn test_reset_circuits() {
        let cfg = LlmConfig::new("openai", "gpt-4o", "sk-test");
        let router = LlmRouter::new(cfg);

        // Trip the circuit
        {
            let mut circuits = router.circuits.lock().unwrap();
            let c = circuits.get_mut("openai:gpt-4o").unwrap();
            for _ in 0..5 { c.record_failure(); }
            assert_eq!(c.state, CircuitState::Open);
        }

        // Reset
        router.reset_circuits();
        let states = router.circuit_states();
        assert_eq!(states["openai:gpt-4o"], CircuitState::Closed);
    }

    #[test]
    fn test_total_cost_accumulates() {
        let cfg = LlmConfig::new("openai", "gpt-4o", "sk-test");
        let router = LlmRouter::new(cfg);

        let resp = LlmResponse {
            text: "Hi".to_string(),
            model: "gpt-4o".to_string(),
            provider: "openai".to_string(),
            input_tokens: 1000,
            output_tokens: 500,
            finish_reason: "stop".to_string(),
        };

        let key = "openai:gpt-4o";
        let cfg = &router.providers[0];
        router.track_cost(key, cfg, &resp);
        router.track_cost(key, cfg, &resp);

        let costs = router.cost_summary();
        let cost = costs.get(key).unwrap();
        assert_eq!(cost.total_requests, 2);
        assert_eq!(cost.total_input_tokens, 2000);
        assert_eq!(cost.total_output_tokens, 1000);
        assert!(router.total_cost_usd() > 0.0);
    }
}
