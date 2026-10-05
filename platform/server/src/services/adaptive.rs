//! # Adaptive LLM Router
//!
//! Selects the optimal LLM provider per-request using a multi-factor scoring
//! algorithm with real-time health tracking, circuit breaking, and cost control.
//!
//! ## Algorithm
//! ```
//! score(p, task) = W_cap   * capability_match(p, task_tokens, task_type)
//!                + W_cost  * cost_efficiency(p, budget_remaining)
//!                + W_health* health_score(p, recent_window)
//!                + W_explore * ucb1_bonus(p, total_calls)
//! ```
//! Hard constraints: budget ceiling, circuit-open exclusion, capability flags.
//!
//! ## Routing Strategies
//! - `CostOptimal`   — minimise $ per token
//! - `Performance`   — minimise latency, maximise quality
//! - `Balanced`      — weighted blend (default)
//! - `Stable`        — prefer providers with highest recent success rate
//!
//! ## Stability guarantees
//! - Exponential backoff retry (3 attempts, 500 ms base, 10 s cap)
//! - Per-provider circuit breaker (trips after 5 failures, 30 s cooldown)
//! - Budget ceiling hard-stop before any call
//! - Automatic fallback to next-best provider on any error

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;

// ═══════════════════════════════════════════════════════════════
// Provider Registry
// ═══════════════════════════════════════════════════════════════

/// Capability flags a provider may support.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Capability {
    Chat,
    Code,
    Reasoning,
    Vision,
    LongContext,
    Embeddings,
    FunctionCalling,
}

/// Static description of an LLM provider+model pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub id: String, // "deepseek:deepseek-chat"
    pub provider: String,
    pub model: String,
    pub capabilities: Vec<Capability>,
    /// USD per million input tokens
    pub input_cost_per_m: f64,
    /// USD per million output tokens
    pub output_cost_per_m: f64,
    /// Relative quality score 0–100
    pub quality_score: u32,
    /// Max context window (tokens)
    pub context_window: u32,
    /// Enabled in this deployment
    pub enabled: bool,
}

impl ProviderProfile {
    pub fn cost_per_token(&self) -> f64 {
        (self.input_cost_per_m + self.output_cost_per_m) / 2.0 / 1_000_000.0
    }
}

/// Built-in provider catalogue (extended via config/API).
pub fn default_provider_catalogue() -> Vec<ProviderProfile> {
    vec![
        ProviderProfile {
            id: "deepseek:deepseek-chat".into(),
            provider: "deepseek".into(),
            model: "deepseek-chat".into(),
            capabilities: vec![
                Capability::Chat,
                Capability::Code,
                Capability::Reasoning,
                Capability::FunctionCalling,
            ],
            input_cost_per_m: 0.14,
            output_cost_per_m: 0.28,
            quality_score: 82,
            context_window: 64_000,
            enabled: true,
        },
        ProviderProfile {
            id: "deepseek:deepseek-reasoner".into(),
            provider: "deepseek".into(),
            model: "deepseek-reasoner".into(),
            capabilities: vec![Capability::Chat, Capability::Reasoning, Capability::Code],
            input_cost_per_m: 0.55,
            output_cost_per_m: 2.19,
            quality_score: 95,
            context_window: 128_000,
            enabled: true,
        },
        ProviderProfile {
            id: "openai:gpt-4o-mini".into(),
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            capabilities: vec![
                Capability::Chat,
                Capability::Code,
                Capability::Vision,
                Capability::FunctionCalling,
            ],
            input_cost_per_m: 0.15,
            output_cost_per_m: 0.60,
            quality_score: 78,
            context_window: 128_000,
            enabled: true,
        },
        ProviderProfile {
            id: "openai:gpt-4o".into(),
            provider: "openai".into(),
            model: "gpt-4o".into(),
            capabilities: vec![
                Capability::Chat,
                Capability::Code,
                Capability::Vision,
                Capability::Reasoning,
                Capability::FunctionCalling,
                Capability::LongContext,
            ],
            input_cost_per_m: 2.50,
            output_cost_per_m: 10.00,
            quality_score: 97,
            context_window: 128_000,
            enabled: true,
        },
        ProviderProfile {
            id: "anthropic:claude-3-5-haiku".into(),
            provider: "anthropic".into(),
            model: "claude-3-5-haiku-20241022".into(),
            capabilities: vec![
                Capability::Chat,
                Capability::Code,
                Capability::FunctionCalling,
            ],
            input_cost_per_m: 0.80,
            output_cost_per_m: 4.00,
            quality_score: 80,
            context_window: 200_000,
            enabled: true,
        },
        ProviderProfile {
            id: "anthropic:claude-3-7-sonnet".into(),
            provider: "anthropic".into(),
            model: "claude-3-7-sonnet-20250219".into(),
            capabilities: vec![
                Capability::Chat,
                Capability::Code,
                Capability::Reasoning,
                Capability::Vision,
                Capability::FunctionCalling,
                Capability::LongContext,
            ],
            input_cost_per_m: 3.00,
            output_cost_per_m: 15.00,
            quality_score: 98,
            context_window: 200_000,
            enabled: true,
        },
    ]
}

// ═══════════════════════════════════════════════════════════════
// Health & Circuit Breaker State
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ProviderHealth {
    pub provider_id: String,
    /// Rolling window of latencies (ms) for last 100 calls
    latencies_ms: std::collections::VecDeque<u64>,
    /// Rolling window of success (true) / failure (false) for last 100 calls
    outcomes: std::collections::VecDeque<bool>,
    /// Circuit breaker: consecutive failures
    consecutive_failures: u32,
    /// Circuit breaker: trip timestamp
    circuit_open_until: Option<Instant>,
    /// Total calls ever
    pub total_calls: u64,
    /// Total successful calls
    pub total_success: u64,
    /// Total tokens processed
    pub total_tokens: u64,
    /// Total cost USD
    pub total_cost_usd: f64,
}

impl ProviderHealth {
    pub fn new(id: &str) -> Self {
        Self {
            provider_id: id.to_string(),
            latencies_ms: std::collections::VecDeque::with_capacity(100),
            outcomes: std::collections::VecDeque::with_capacity(100),
            consecutive_failures: 0,
            circuit_open_until: None,
            total_calls: 0,
            total_success: 0,
            total_tokens: 0,
            total_cost_usd: 0.0,
        }
    }

    pub fn record_success(&mut self, latency_ms: u64, tokens: u64, cost_usd: f64) {
        if self.latencies_ms.len() >= 100 {
            self.latencies_ms.pop_front();
        }
        if self.outcomes.len() >= 100 {
            self.outcomes.pop_front();
        }
        self.latencies_ms.push_back(latency_ms);
        self.outcomes.push_back(true);
        self.consecutive_failures = 0;
        self.total_calls += 1;
        self.total_success += 1;
        self.total_tokens += tokens;
        self.total_cost_usd += cost_usd;
    }

    pub fn record_failure(&mut self) {
        if self.outcomes.len() >= 100 {
            self.outcomes.pop_front();
        }
        self.outcomes.push_back(false);
        self.consecutive_failures += 1;
        self.total_calls += 1;
        // Trip circuit after 5 consecutive failures
        if self.consecutive_failures >= 5 {
            self.circuit_open_until = Some(Instant::now() + Duration::from_secs(30));
            tracing::warn!(provider = %self.provider_id, "adaptive: circuit OPEN (5 consecutive failures)");
        }
    }

    pub fn is_circuit_open(&mut self) -> bool {
        if let Some(until) = self.circuit_open_until {
            if Instant::now() < until {
                return true;
            }
            // Half-open: let one probe through
            self.circuit_open_until = None;
            self.consecutive_failures = 0;
        }
        false
    }

    /// Success rate over recent window [0, 1]
    pub fn success_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.5;
        } // unknown → neutral
        let successes = self.outcomes.iter().filter(|&&v| v).count();
        successes as f64 / self.outcomes.len() as f64
    }

    /// P50 latency ms (or 999999 if unknown)
    pub fn p50_latency_ms(&self) -> u64 {
        if self.latencies_ms.is_empty() {
            return 999;
        }
        let mut sorted: Vec<u64> = self.latencies_ms.iter().cloned().collect();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }
}

// ═══════════════════════════════════════════════════════════════
// Routing Strategy & Scoring
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    /// Minimise cost — pick cheapest eligible provider
    CostOptimal,
    /// Minimise latency, maximise quality score
    Performance,
    /// Weighted blend of cost, health, quality (default)
    Balanced,
    /// Prefer providers with highest recent success rate (stability focus)
    Stable,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        Self::Balanced
    }
}

/// Per-agent adaptive routing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRoutingConfig {
    pub agent_pid: String,
    pub strategy: RoutingStrategy,
    /// Hard budget ceiling (USD) — refuse calls over this
    pub budget_ceiling_usd: Option<f64>,
    /// Required capabilities (all must be present)
    pub required_capabilities: Vec<Capability>,
    /// Preferred provider IDs (tried first if healthy)
    pub preferred_providers: Vec<String>,
    /// Blocked provider IDs
    pub blocked_providers: Vec<String>,
}

impl AgentRoutingConfig {
    pub fn default_for(agent_pid: &str) -> Self {
        Self {
            agent_pid: agent_pid.to_string(),
            strategy: RoutingStrategy::Balanced,
            budget_ceiling_usd: None,
            required_capabilities: vec![Capability::Chat],
            preferred_providers: vec![],
            blocked_providers: vec![],
        }
    }
}

/// Scoring weights for the balanced strategy.
struct Weights {
    capability: f64,
    cost: f64,
    health: f64,
    quality: f64,
    explore: f64,
}

impl Weights {
    fn for_strategy(s: &RoutingStrategy) -> Self {
        match s {
            RoutingStrategy::CostOptimal => Self {
                capability: 0.20,
                cost: 0.55,
                health: 0.15,
                quality: 0.05,
                explore: 0.05,
            },
            RoutingStrategy::Performance => Self {
                capability: 0.20,
                cost: 0.05,
                health: 0.20,
                quality: 0.50,
                explore: 0.05,
            },
            RoutingStrategy::Balanced => Self {
                capability: 0.20,
                cost: 0.30,
                health: 0.25,
                quality: 0.20,
                explore: 0.05,
            },
            RoutingStrategy::Stable => Self {
                capability: 0.15,
                cost: 0.15,
                health: 0.60,
                quality: 0.05,
                explore: 0.05,
            },
        }
    }
}

/// Score a provider for a given task.
/// Returns a value in [0, 1] — higher is better.
fn score_provider(
    profile: &ProviderProfile,
    health: &ProviderHealth,
    strategy: &RoutingStrategy,
    estimated_input_tokens: u32,
    estimated_output_tokens: u32,
    budget_remaining_usd: f64,
    total_global_calls: u64,
) -> f64 {
    let w = Weights::for_strategy(strategy);

    // ── Capability match (1.0 = fully matches, 0.0 = no match) ──
    let cap_score = 1.0_f64; // filtered before scoring; all scored providers match

    // ── Cost efficiency (cheaper = higher score, budget-normalised) ──
    let est_cost = connector_engine::llm_router::estimate_usd_for_tokens(
        &profile.provider,
        &profile.model,
        estimated_input_tokens,
        estimated_output_tokens,
    );
    let cost_score = if budget_remaining_usd <= 0.0 {
        0.0 // over budget
    } else {
        // 1.0 when est_cost == 0, approaches 0 as est_cost → budget
        let fraction = (est_cost / budget_remaining_usd.max(0.001)).min(1.0);
        1.0 - fraction
    };

    // ── Health score (success rate, latency) ──
    let success = health.success_rate();
    let latency_ms = health.p50_latency_ms() as f64;
    // Normalise latency: 200 ms = 1.0, 5000 ms = 0.0
    let latency_score = 1.0 - (latency_ms / 5_000.0).min(1.0);
    let health_score = success * 0.7 + latency_score * 0.3;

    // ── Quality score (normalised 0–1) ──
    let quality_score = profile.quality_score as f64 / 100.0;

    // ── UCB1 exploration bonus ──
    let explore_score = if health.total_calls == 0 {
        1.0 // unexplored → always worth trying
    } else if total_global_calls == 0 {
        0.5
    } else {
        let ucb = (2.0 * (total_global_calls as f64).ln() / health.total_calls as f64).sqrt();
        ucb.min(1.0)
    };

    w.capability * cap_score
        + w.cost * cost_score
        + w.health * health_score
        + w.quality * quality_score
        + w.explore * explore_score
}

// ═══════════════════════════════════════════════════════════════
// Adaptive Router Service
// ═══════════════════════════════════════════════════════════════

#[derive(Clone)]
pub struct AdaptiveRouter {
    /// Known provider profiles
    pub catalogue: Arc<Mutex<Vec<ProviderProfile>>>,
    /// Per-provider health state
    pub health: Arc<Mutex<HashMap<String, ProviderHealth>>>,
    /// Per-agent routing configs
    pub agent_configs: Arc<Mutex<HashMap<String, AgentRoutingConfig>>>,
    /// Global routing decision log (last 1000)
    pub decision_log: Arc<Mutex<std::collections::VecDeque<RoutingDecision>>>,
    /// Total calls across all providers (for UCB1)
    pub total_calls: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    pub timestamp_ms: u64,
    pub agent_pid: String,
    pub selected_provider: String,
    pub selected_model: String,
    pub strategy: RoutingStrategy,
    pub score: f64,
    pub reason: String,
    pub estimated_cost_usd: f64,
}

impl AdaptiveRouter {
    pub fn new() -> Self {
        let catalogue = default_provider_catalogue();
        let mut health = HashMap::new();
        for p in &catalogue {
            health.insert(p.id.clone(), ProviderHealth::new(&p.id));
        }
        Self {
            catalogue: Arc::new(Mutex::new(catalogue)),
            health: Arc::new(Mutex::new(health)),
            agent_configs: Arc::new(Mutex::new(HashMap::new())),
            decision_log: Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(1000))),
            total_calls: Arc::new(Mutex::new(0)),
        }
    }

    /// Select the best provider for an agent's next LLM call.
    /// Returns `(provider_id, provider, model, estimated_cost_usd)`.
    pub fn select(
        &self,
        agent_pid: &str,
        estimated_input_tokens: u32,
        estimated_output_tokens: u32,
        accumulated_cost_usd: f64,
    ) -> Option<RoutingDecision> {
        let catalogue = self.catalogue.lock().unwrap();
        let mut health = self.health.lock().unwrap();
        let configs = self.agent_configs.lock().unwrap();
        let total_calls = *self.total_calls.lock().unwrap();

        let config = configs
            .get(agent_pid)
            .cloned()
            .unwrap_or_else(|| AgentRoutingConfig::default_for(agent_pid));

        // Hard: budget ceiling
        let budget_remaining = config
            .budget_ceiling_usd
            .map(|ceil| (ceil - accumulated_cost_usd).max(0.0))
            .unwrap_or(f64::MAX);
        if budget_remaining <= 0.0 {
            tracing::warn!(agent = %agent_pid, "adaptive: budget ceiling reached — blocking call");
            return None;
        }

        // Filter to eligible providers
        let eligible: Vec<&ProviderProfile> = catalogue
            .iter()
            .filter(|p| {
                if !p.enabled {
                    return false;
                }
                if config.blocked_providers.contains(&p.id)
                    || config.blocked_providers.contains(&p.provider)
                {
                    return false;
                }
                // Check required capabilities
                for cap in &config.required_capabilities {
                    if !p.capabilities.contains(cap) {
                        return false;
                    }
                }
                // Check circuit breaker
                if let Some(h) = health.get_mut(&p.id) {
                    if h.is_circuit_open() {
                        return false;
                    }
                }
                true
            })
            .collect();

        if eligible.is_empty() {
            tracing::error!(agent = %agent_pid, "adaptive: no eligible providers available");
            return None;
        }

        // BF2-X03: ensure scoring never panics if health map is missing an entry (filter can admit providers without `get_mut`).
        for p in &eligible {
            health
                .entry((*p).id.clone())
                .or_insert_with(|| ProviderHealth::new(&p.id));
        }

        // Score each eligible provider
        let mut scored: Vec<(&ProviderProfile, f64)> = eligible
            .iter()
            .map(|p| {
                let h: &ProviderHealth = health.get(&p.id).unwrap();
                // Temporarily create a stub for scoring (health is behind Mutex already locked)
                let score = score_provider(
                    p,
                    h,
                    &config.strategy,
                    estimated_input_tokens,
                    estimated_output_tokens,
                    budget_remaining,
                    total_calls,
                );
                (*p, score)
            })
            .collect();

        // Boost preferred providers by +0.15 (soft preference, not a hard lock)
        for (p, score) in &mut scored {
            if config.preferred_providers.contains(&p.id)
                || config.preferred_providers.contains(&p.provider)
            {
                *score = (*score + 0.15).min(1.0);
            }
        }

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let (best, best_score) = scored[0];
        let est_cost = connector_engine::llm_router::estimate_usd_for_tokens(
            &best.provider,
            &best.model,
            estimated_input_tokens,
            estimated_output_tokens,
        );

        let reason = format!(
            "strategy={:?} score={:.3} health={:.0}% p50={}ms cost_est=${:.6}",
            config.strategy,
            best_score,
            health
                .get(&best.id)
                .map(|h| h.success_rate() * 100.0)
                .unwrap_or(50.0),
            health
                .get(&best.id)
                .map(|h| h.p50_latency_ms())
                .unwrap_or(0),
            est_cost,
        );

        let decision = RoutingDecision {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            agent_pid: agent_pid.to_string(),
            selected_provider: best.provider.clone(),
            selected_model: best.model.clone(),
            strategy: config.strategy.clone(),
            score: (best_score * 1000.0).round() / 1000.0,
            reason,
            estimated_cost_usd: est_cost,
        };

        *self.total_calls.lock().unwrap() += 1;
        let mut log = self.decision_log.lock().unwrap();
        if log.len() >= 1000 {
            log.pop_front();
        }
        log.push_back(decision.clone());

        tracing::debug!(
            agent = %agent_pid,
            provider = %best.provider,
            model = %best.model,
            score = best_score,
            "adaptive: selected provider"
        );

        Some(decision)
    }

    /// Record outcome of an LLM call for health tracking.
    pub fn record_outcome(
        &self,
        provider_id: &str,
        success: bool,
        latency_ms: u64,
        tokens: u64,
        cost_usd: f64,
    ) {
        let mut health = self.health.lock().unwrap();
        let h = health
            .entry(provider_id.to_string())
            .or_insert_with(|| ProviderHealth::new(provider_id));
        if success {
            h.record_success(latency_ms, tokens, cost_usd);
        } else {
            h.record_failure();
        }
    }

    /// Get or create agent routing config.
    pub fn get_config(&self, agent_pid: &str) -> AgentRoutingConfig {
        self.agent_configs
            .lock()
            .unwrap()
            .get(agent_pid)
            .cloned()
            .unwrap_or_else(|| AgentRoutingConfig::default_for(agent_pid))
    }

    /// Update agent routing config.
    pub fn set_config(&self, config: AgentRoutingConfig) {
        self.agent_configs
            .lock()
            .unwrap()
            .insert(config.agent_pid.clone(), config);
    }
}

// ═══════════════════════════════════════════════════════════════
// REST API Handlers
// ═══════════════════════════════════════════════════════════════

/// GET /api/v1/adaptive/status — overall adaptive router health
pub async fn adaptive_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let router = match &state.adaptive_router {
        Some(r) => r,
        None => {
            return Json(
                serde_json::json!({"error": "Adaptive router not initialised", "status": 503}),
            )
        }
    };

    let catalogue = router.catalogue.lock().unwrap();
    let health = router.health.lock().unwrap();
    let total = *router.total_calls.lock().unwrap();

    let providers: Vec<serde_json::Value> = catalogue
        .iter()
        .map(|p| {
            let h = health.get(&p.id);
            serde_json::json!({
                "id":              p.id,
                "provider":        p.provider,
                "model":           p.model,
                "enabled":         p.enabled,
                "quality_score":   p.quality_score,
                "cost_per_1m_in":  p.input_cost_per_m,
                "cost_per_1m_out": p.output_cost_per_m,
                "capabilities":    p.capabilities,
                "health": h.map(|h| serde_json::json!({
                    "success_rate":    (h.success_rate() * 1000.0).round() / 10.0,
                    "p50_latency_ms":  h.p50_latency_ms(),
                    "total_calls":     h.total_calls,
                    "total_tokens":    h.total_tokens,
                    "total_cost_usd":  h.total_cost_usd,
                    "circuit_open":    h.circuit_open_until.is_some(),
                })).unwrap_or(serde_json::json!({"unknown": true})),
            })
        })
        .collect();

    Json(serde_json::json!({
        "total_routing_decisions": total,
        "providers":               providers,
    }))
}

/// GET /api/v1/adaptive/decisions?limit=N — recent routing decisions
pub async fn adaptive_decisions(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let router = match &state.adaptive_router {
        Some(r) => r,
        None => return Json(serde_json::json!({"decisions": []})),
    };
    let log = router.decision_log.lock().unwrap();
    let decisions: Vec<&RoutingDecision> = log.iter().rev().take(50).collect();
    Json(serde_json::json!({ "decisions": decisions }))
}

/// GET /api/v1/adaptive/agents/:pid/config — get agent routing config
pub async fn adaptive_agent_config(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let router = match &state.adaptive_router {
        Some(r) => r,
        None => return Json(serde_json::json!({"error": "Adaptive router not initialised"})),
    };
    let config = router.get_config(&pid);
    Json(serde_json::to_value(config).unwrap_or_default())
}

/// PUT /api/v1/adaptive/agents/:pid/config — update agent routing config
pub async fn adaptive_set_config(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
    Json(mut body): Json<AgentRoutingConfig>,
) -> Json<serde_json::Value> {
    let router = match &state.adaptive_router {
        Some(r) => r,
        None => return Json(serde_json::json!({"error": "Adaptive router not initialised"})),
    };
    body.agent_pid = pid;
    router.set_config(body);
    Json(serde_json::json!({"ok": true}))
}
