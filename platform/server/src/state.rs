use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use vac_core::kernel::MemoryKernel;
use vac_core::knot::KnotEngine;
use vac_core::store::KernelStore;
use connector_engine::engine_store::EngineStore;
use connector_engine::storage_zone::StorageLayout;
use connector_engine::aapi::ActionEngine;
use connector_engine::binding::BindingEngine;
use connector_engine::trust::TrustComputer;
use connector_engine::llm_router::{LlmRouter, RouterConfig};
use connector_engine::llm::LlmConfig as EngineLlmConfig;
use connector_engine::guard_pipeline::GuardPipeline;
// ── Sellable service OSS primitives ──
use connector_engine::secret_store::SecretStore;
use connector_engine::grounding::GroundingTable;
use connector_engine::claims::ClaimVerifier;
use connector_engine::reputation::{ReputationEngine, ReputationConfig};
use connector_engine::escrow::EscrowManager;
use connector_engine::negotiation::NegotiationManager;
use connector_engine::pricing::DynamicPricer;
use connector_engine::agent_index::AgentIndex;
use connector_engine::orchestrator::Orchestrator;
use connector_engine::saga_bridge::PipelineManager;
use connector_engine::context_manager::ContextManager;
use connector_engine::adaptive_threshold::AdaptiveThresholdManager;

use crate::config::PlatformConfig;
use crate::license::LicenseInfo;
use crate::auth::UserStore;
use crate::services::runtime_control::{IsolationRuntime, RuntimeMode};
use crate::services::payment::PaymentProvider;
use crate::signing::PlatformSigningKey;
use crate::services::registry::AgentRegistry;
use crate::services::playground::PlaygroundStore;

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub endpoint: Option<String>,
}

/// Liveness plane — `/health` must never wait on `kernel` / VAC locks.
/// Updated on agent register/delete/boot; read with atomics only.
#[derive(Debug, Default)]
pub struct HealthSnapshot {
    pub agents: AtomicUsize,
    pub agent_cap: AtomicU32,
}

impl HealthSnapshot {
    pub fn set_agents(&self, n: usize) {
        self.agents.store(n, Ordering::Relaxed);
    }

    pub fn set_agent_cap(&self, n: u32) {
        self.agent_cap.store(n, Ordering::Relaxed);
    }

    pub fn agents(&self) -> usize {
        self.agents.load(Ordering::Relaxed)
    }

    pub fn agent_cap(&self) -> u32 {
        self.agent_cap.load(Ordering::Relaxed)
    }
}

pub struct PlatformState {
    pub kernel: Mutex<MemoryKernel>,
    /// Ring 0 persistent store (redb CoW B-tree).
    /// Used for flush_to_store (periodic) and load_from_store (startup recovery).
    pub kernel_store: Mutex<Box<dyn KernelStore + Send>>,
    pub knot: Mutex<KnotEngine>,
    pub binding: Mutex<BindingEngine>,
    pub aapi: Mutex<ActionEngine>,
    pub engine_store: Mutex<Box<dyn EngineStore + Send>>,
    pub runtime_mode: std::sync::RwLock<RuntimeMode>,
    pub isolation_runtime: std::sync::RwLock<IsolationRuntime>,
    pub storage_layout: StorageLayout,
    pub config: PlatformConfig,
    pub license: LicenseInfo,
    /// Atomic agent counts for `/health` — never takes the kernel mutex.
    pub health: HealthSnapshot,
    pub metrics: PlatformMetrics,
    /// Phase 1.10.1 native observability ring buffer (request-level in-memory samples).
    pub observability: Mutex<crate::services::observability::NativeObservabilityStore>,
    /// Hot-swappable primary LLM config (DI-1 — Settings / `connectorctl llm link`).
    pub llm_config: RwLock<Option<LlmConfig>>,
    pub user_store: Mutex<UserStore>,
    /// Production LLM router: retry, fallback, circuit breaker, cost tracking.
    /// `None` when no LLM provider is configured. Wrapped for runtime link/reload.
    pub llm_router: RwLock<Option<Arc<LlmRouter>>>,
    /// 5-layer guard pipeline: MAC + Policy + Content + CircuitBreaker + HITL.
    pub guard: Mutex<GuardPipeline>,
    /// Payment provider (Stripe via async-stripe, or NoopProvider when unconfigured).
    pub payment: Box<dyn PaymentProvider>,
    /// Ed25519 signing keypair — signs trust certificates and audit exports.
    /// Loaded from $DATA_DIR/keys/platform_signing.key (mode 0600).
    pub signing_key: PlatformSigningKey,
    // ── Sellable services (OSS primitives surfaced as platform features) ──
    /// Kernel-only secret storage with opaque handles and TTL.
    pub secret_store: Mutex<SecretStore>,
    /// Deterministic grounding tables (ICD-10, CPT, statutes → standardized codes).
    pub grounding: Mutex<GroundingTable>,
    /// Claims verification engine — LLM assertions → Explicit/Implied/Absent.
    pub claim_verifier: ClaimVerifier,
    /// EigenTrust-based agent reputation with Sybil resistance.
    pub reputation: Mutex<ReputationEngine>,
    /// Trustless agent-to-agent escrow with settlement.
    pub escrow: Mutex<EscrowManager>,
    /// Multi-round contract negotiation between agents.
    pub negotiation: Mutex<NegotiationManager>,
    /// Surge pricing, volume discounts, budget gates.
    pub pricer: Mutex<DynamicPricer>,
    /// Agent capability index with inverted lookup.
    pub agent_index: Mutex<AgentIndex>,
    /// DAG-based pipeline orchestrator with retry.
    pub orchestrator: Mutex<Orchestrator>,
    /// Saga pipeline manager with rollback coordination.
    pub pipeline_mgr: Mutex<PipelineManager>,
    /// Agent context snapshot/restore/compress/evict lifecycle.
    pub context_mgr: Mutex<ContextManager>,
    /// Per-agent adaptive firewall threshold adjustment.
    pub adaptive_thresholds: Mutex<AdaptiveThresholdManager>,
    /// AIOS-A6: Versioned agent manifest registry (deploy/rollback/diff).
    pub registry: Mutex<AgentRegistry>,
    /// Adaptive LLM router: multi-factor provider scoring, health tracking, circuit breaker.
    /// None when no multi-provider config is present.
    pub adaptive_router: Option<crate::services::adaptive::AdaptiveRouter>,
    /// Knowledge Transfer Graph: inter-agent knowledge flow tracking and routing.
    pub knowledge_graph: Option<crate::services::knowledge_transfer::KnowledgeGraph>,
    /// Phase A host kernel contract (profiles, attach/release, admission integration) until `connector-kerneld` exists.
    pub kernel_host: Mutex<crate::services::kernel_host::KernelHostState>,
    /// Phase 5.4 — per-plugin cold/warm/hot tier + cold-start coalescing (in-memory until wired to spawns).
    pub plugin_tier_scheduler: Arc<crate::services::plugin_tier_scheduler::PluginTierScheduler>,
    /// Phase 5.10 — crash / quarantine counters (in-memory; supervisor should call `record_failure`).
    pub plugin_crash_recovery: Arc<crate::services::plugin_crash_recovery::PluginCrashRecovery>,
    /// Playground: in-memory TTL session store (only populated when CONNECTOR_PLAYGROUND=1).
    pub playground_sessions: PlaygroundStore,
    /// Ring-0 flush tracker (last successful redb checkpoint).
    pub kernel_durability: KernelDurabilityTracker,
    /// Per-agent Intelligence Access Cells (epoch, inflight, read-set).
    pub cells: crate::concurrency::intelligence_cell::CellRegistry,
    /// Compiled immutable AgentRuntimeSnapshot values (atomic publish).
    pub runtime_snapshots: crate::substrate::agent_runtime_snapshot::RuntimeSnapshotRegistry,
    /// Session single-writer leases (Talk plane).
    pub session_owners: crate::concurrency::session_owner::SessionOwnerRegistry,
    /// Per-plane concurrency bulkheads (Talk / Effect / Control).
    pub bulkheads: crate::concurrency::workload_bulkhead::WorkloadBulkheads,
}

/// Tracks last kernel → redb flush for substrate/forensics honesty.
#[derive(Debug, Default)]
pub struct KernelDurabilityTracker {
    pub last_flush_ms: std::sync::atomic::AtomicI64,
    pub last_flush_objects: std::sync::atomic::AtomicU64,
    pub last_flush_error: std::sync::Mutex<Option<String>>,
    pub write_through_total: std::sync::atomic::AtomicU64,
}

impl PlatformState {
    /// Refresh [`HealthSnapshot`] from the live kernel (call after register/delete/boot).
    pub fn refresh_health_snapshot(&self) {
        let n = self
            .kernel
            .lock()
            .map(|k| k.all_agents().len())
            .unwrap_or(0);
        self.health.set_agents(n);
        let cap = crate::services::agents::resolved_kernel_agent_cap(self);
        self.health.set_agent_cap(cap);
    }

    pub fn trust_score(&self) -> connector_engine::trust::TrustScore {
        let k = self.kernel.lock().unwrap();
        TrustComputer::compute(&k)
    }

    /// Whether Talk / gateway has a live router (DI-1).
    pub fn llm_wired(&self) -> bool {
        self.llm_router
            .read()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    /// Cloneable handle for async completions (do not hold the RwLock across `.await`).
    pub fn llm_router_arc(&self) -> Option<Arc<LlmRouter>> {
        self.llm_router
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(Arc::clone))
    }

    pub fn llm_config_snapshot(&self) -> Option<LlmConfig> {
        self.llm_config.read().ok().and_then(|g| g.clone())
    }

    /// Rebuild router from provider list and install (keys stay on platform — never cage env).
    pub fn install_llm_router(&self, config: LlmConfig, router: LlmRouter) {
        if let Ok(mut g) = self.llm_config.write() {
            *g = Some(config);
        }
        if let Ok(mut g) = self.llm_router.write() {
            *g = Some(Arc::new(router));
        }
    }
}

/// Build an `LlmRouter` from one or more engine configs (boot + DI-1 link).
pub fn build_llm_router(providers: Vec<EngineLlmConfig>) -> LlmRouter {
    let mut config = RouterConfig::default();
    if let Ok(raw) = std::env::var("CONNECTOR_LLM_MAX_RETRIES") {
        if let Ok(n) = raw.parse::<u32>() {
            config.retry.max_retries = n;
        }
    }
    LlmRouter::with_fallbacks(providers, config)
}

/// Label set for per-agent metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct AgentLabels {
    pub agent_pid: String,
}

/// Label set for per-namespace metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct NamespaceLabels {
    pub namespace: String,
}

/// Label set for rejection reason metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct ReasonLabels {
    pub reason: String,
}

pub struct PlatformMetrics {
    pub registry: prometheus_client::registry::Registry,
    pub requests_total: prometheus_client::metrics::counter::Counter,
    pub trust_score: prometheus_client::metrics::gauge::Gauge<f64, std::sync::atomic::AtomicU64>,
    pub pipeline_duration_ms: prometheus_client::metrics::histogram::Histogram,
    pub events_total: prometheus_client::metrics::counter::Counter,
    pub actions_authorized: prometheus_client::metrics::counter::Counter,
    pub actions_denied: prometheus_client::metrics::counter::Counter,
    // I11: agent-specific metrics (unlabeled — aggregate across all agents)
    /// Total tokens consumed across all agents (cumulative)
    pub tokens_consumed_total: prometheus_client::metrics::counter::Counter,
    /// Gauge — number of agents currently in Running status
    pub agents_active: prometheus_client::metrics::gauge::Gauge,
    /// Gauge — number of agents currently Suspended (KECS < 0.60 or manual)
    pub agents_suspended: prometheus_client::metrics::gauge::Gauge,
    /// Total LLM calls proxied through the AI Gateway
    pub llm_calls_total: prometheus_client::metrics::counter::Counter,
    /// LLM calls that were blocked by injection detection
    pub llm_injections_blocked: prometheus_client::metrics::counter::Counter,
    /// Total billing usage events recorded
    pub billing_usage_events: prometheus_client::metrics::counter::Counter,
    /// Total account signups
    pub signups_total: prometheus_client::metrics::counter::Counter,
    /// KECS auto-suspend actions taken
    pub kecs_suspensions_total: prometheus_client::metrics::counter::Counter,
    /// BAA/DPA agreements accepted
    pub legal_agreements_total: prometheus_client::metrics::counter::Counter,
    // DX-P2-5: Per-label metrics for per-agent / per-namespace breakdowns
    /// Tokens consumed per agent_pid label
    pub tokens_by_agent: prometheus_client::metrics::family::Family<AgentLabels, prometheus_client::metrics::counter::Counter>,
    /// LLM calls per agent_pid label
    pub llm_calls_by_agent: prometheus_client::metrics::family::Family<AgentLabels, prometheus_client::metrics::counter::Counter>,
    /// Injections blocked per agent_pid label
    pub injections_by_agent: prometheus_client::metrics::family::Family<AgentLabels, prometheus_client::metrics::counter::Counter>,
    /// Active agents per namespace label
    pub agents_active_by_ns: prometheus_client::metrics::family::Family<NamespaceLabels, prometheus_client::metrics::gauge::Gauge>,
    /// Context window utilization per agent_pid (0.0-100.0)
    pub context_utilization_by_agent: prometheus_client::metrics::family::Family<AgentLabels, prometheus_client::metrics::gauge::Gauge<f64, std::sync::atomic::AtomicU64>>,
    /// Admission rejections by reason label
    pub admission_rejected_total: prometheus_client::metrics::family::Family<ReasonLabels, prometheus_client::metrics::counter::Counter>,
    /// Host kernel stub: admission denied because attachment not active while `CONNECTOR_KERNEL_ENFORCE=1`.
    pub kernel_host_admission_denied_total: prometheus_client::metrics::counter::Counter,
    pub kernel_profile_upserts_total: prometheus_client::metrics::counter::Counter,
    pub kernel_attach_success_total: prometheus_client::metrics::counter::Counter,
    pub kernel_attach_failures_total: prometheus_client::metrics::counter::Counter,
    pub kernel_release_total: prometheus_client::metrics::counter::Counter,
}

impl PlatformMetrics {
    pub fn new() -> Self {
        use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::{Histogram, exponential_buckets}};
        let mut registry = prometheus_client::registry::Registry::default();

        let requests_total = Counter::default();
        registry.register("connector_requests_total", "Total HTTP API requests handled", requests_total.clone());

        let trust_score = Gauge::<f64, std::sync::atomic::AtomicU64>::default();
        registry.register("connector_trust_score", "Current kernel trust score [0,100]", trust_score.clone());

        let pipeline_duration_ms = Histogram::new(exponential_buckets(1.0, 2.0, 15));
        registry.register("connector_pipeline_duration_ms", "Guard pipeline latency in milliseconds", pipeline_duration_ms.clone());

        let events_total = Counter::default();
        registry.register("connector_events_total", "Total audit events emitted", events_total.clone());

        let actions_authorized = Counter::default();
        registry.register("connector_actions_authorized_total", "Total actions authorized by MAC guard", actions_authorized.clone());

        let actions_denied = Counter::default();
        registry.register("connector_actions_denied_total", "Total actions denied by MAC guard or policy", actions_denied.clone());

        // I11: agent-specific metrics
        let tokens_consumed_total = Counter::default();
        registry.register("connector_tokens_consumed_total", "Total tokens consumed across all agents", tokens_consumed_total.clone());

        let agents_active = Gauge::default();
        registry.register("connector_agents_active", "Number of agents currently in Running status", agents_active.clone());

        let agents_suspended = Gauge::default();
        registry.register("connector_agents_suspended", "Number of agents in Suspended status (KECS auto-suspend or manual)", agents_suspended.clone());

        let llm_calls_total = Counter::default();
        registry.register("connector_llm_calls_total", "Total LLM calls proxied through the AI Gateway", llm_calls_total.clone());

        let llm_injections_blocked = Counter::default();
        registry.register("connector_llm_injections_blocked_total", "LLM calls blocked by SemanticInjectionDetector", llm_injections_blocked.clone());

        let billing_usage_events = Counter::default();
        registry.register("connector_billing_usage_events_total", "Total billing usage events recorded", billing_usage_events.clone());

        let signups_total = Counter::default();
        registry.register("connector_signups_total", "Total new account signups via POST /auth/signup", signups_total.clone());

        let kecs_suspensions_total = Counter::default();
        registry.register("connector_kecs_suspensions_total", "Total KECS auto-suspend actions taken", kecs_suspensions_total.clone());

        let legal_agreements_total = Counter::default();
        registry.register("connector_legal_agreements_total", "Total BAA/DPA agreements accepted", legal_agreements_total.clone());

        // DX-P2-5: Per-label Family metrics
        use prometheus_client::metrics::family::Family;
        let tokens_by_agent: Family<AgentLabels, Counter> = Family::default();
        registry.register(
            "connector_tokens_consumed_by_agent",
            "Tokens consumed per agent_pid",
            tokens_by_agent.clone(),
        );
        let llm_calls_by_agent: Family<AgentLabels, Counter> = Family::default();
        registry.register(
            "connector_llm_calls_by_agent",
            "LLM calls per agent_pid",
            llm_calls_by_agent.clone(),
        );
        let injections_by_agent: Family<AgentLabels, Counter> = Family::default();
        registry.register(
            "connector_llm_injections_blocked_by_agent",
            "Injection-blocked LLM calls per agent_pid",
            injections_by_agent.clone(),
        );
        let agents_active_by_ns: Family<NamespaceLabels, prometheus_client::metrics::gauge::Gauge> = Family::default();
        registry.register(
            "connector_agents_active_by_namespace",
            "Active agent count per namespace",
            agents_active_by_ns.clone(),
        );
        let context_utilization_by_agent: Family<AgentLabels, Gauge<f64, std::sync::atomic::AtomicU64>> = Family::default();
        registry.register(
            "connector_context_utilization_pct",
            "Context window utilization percentage per agent_pid",
            context_utilization_by_agent.clone(),
        );
        let admission_rejected_total: Family<ReasonLabels, Counter> = Family::default();
        registry.register(
            "connector_admission_rejected_total",
            "Admission rejections by reason",
            admission_rejected_total.clone(),
        );

        let kernel_host_admission_denied_total = Counter::default();
        registry.register(
            "connector_kernel_host_admission_denied_total",
            "Admission denials: CONNECTOR_KERNEL_ENFORCE without active host attachment",
            kernel_host_admission_denied_total.clone(),
        );
        let kernel_profile_upserts_total = Counter::default();
        registry.register(
            "connector_kernel_profile_upserts_total",
            "POST /kernel/profiles (idempotent upserts)",
            kernel_profile_upserts_total.clone(),
        );
        let kernel_attach_success_total = Counter::default();
        registry.register(
            "connector_kernel_attach_success_total",
            "Successful kernel attach operations",
            kernel_attach_success_total.clone(),
        );
        let kernel_attach_failures_total = Counter::default();
        registry.register(
            "connector_kernel_attach_failures_total",
            "Failed kernel attach operations",
            kernel_attach_failures_total.clone(),
        );
        let kernel_release_total = Counter::default();
        registry.register(
            "connector_kernel_release_total",
            "Kernel release operations",
            kernel_release_total.clone(),
        );

        Self {
            registry,
            requests_total,
            trust_score,
            pipeline_duration_ms,
            events_total,
            actions_authorized,
            actions_denied,
            tokens_consumed_total,
            agents_active,
            agents_suspended,
            llm_calls_total,
            llm_injections_blocked,
            billing_usage_events,
            signups_total,
            kecs_suspensions_total,
            legal_agreements_total,
            tokens_by_agent,
            llm_calls_by_agent,
            injections_by_agent,
            agents_active_by_ns,
            context_utilization_by_agent,
            admission_rejected_total,
            kernel_host_admission_denied_total,
            kernel_profile_upserts_total,
            kernel_attach_success_total,
            kernel_attach_failures_total,
            kernel_release_total,
        }
    }

    pub fn encode(&self) -> String {
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &self.registry).unwrap_or_default();
        buf
    }
}

pub type SharedState = Arc<PlatformState>;
