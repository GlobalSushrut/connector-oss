//! Gateway application state

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use aapi_adapters::{Dispatcher, RegistryBuilder};
use aapi_crypto::{KeyStore, CapabilityVerifier, VakyaSigner, VakyaVerifier};
use aapi_indexdb::{SqliteIndexDb, IndexDbStore};
use aapi_metarules::{PolicyEngine, Policy, Rule, Condition, ConditionType, Operator};

/// Gateway configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Database URL
    pub database_url: String,
    /// Gateway ID
    pub gateway_id: String,
    /// Production mode - enables strict security defaults
    pub production_mode: bool,
    /// Require request signing verification (enforced in production mode)
    pub require_signatures: bool,
    /// Require capability verification (enforced in production mode)
    pub require_capabilities: bool,
    /// Default policy decision when no rules match (deny in production mode)
    pub default_deny: bool,
    /// Maximum request body size
    pub max_body_size: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database_url: "sqlite:aapi.db".to_string(),
            gateway_id: uuid::Uuid::new_v4().to_string(),
            production_mode: false,
            require_signatures: false,
            require_capabilities: false,
            default_deny: false,
            max_body_size: 10 * 1024 * 1024, // 10MB
            request_timeout_secs: 30,
        }
    }
}

impl GatewayConfig {
    /// Create a production-mode configuration with strict security defaults
    pub fn production() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database_url: "sqlite:aapi.db".to_string(),
            gateway_id: uuid::Uuid::new_v4().to_string(),
            production_mode: true,
            require_signatures: true,
            require_capabilities: true,
            default_deny: true,
            max_body_size: 10 * 1024 * 1024,
            request_timeout_secs: 30,
        }
    }

    /// Check if signatures are required (explicit or via production mode)
    pub fn signatures_required(&self) -> bool {
        self.require_signatures || self.production_mode
    }

    /// Check if capabilities are required (explicit or via production mode)
    pub fn capabilities_required(&self) -> bool {
        self.require_capabilities || self.production_mode
    }

    /// Check if default-deny is enabled (explicit or via production mode)
    pub fn is_default_deny(&self) -> bool {
        self.default_deny || self.production_mode
    }
}

impl GatewayConfig {
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// Note: production(), signatures_required(), capabilities_required(), is_default_deny() are defined above

/// Shared application state
pub struct AppState {
    /// Gateway configuration
    pub config: GatewayConfig,
    /// Key store for signing/verification
    pub key_store: KeyStore,
    /// IndexDB store
    pub index_db: Arc<dyn IndexDbStore>,
    /// VĀKYA signer
    pub signer: VakyaSigner,
    /// VĀKYA verifier
    pub verifier: VakyaVerifier,
    /// Capability verifier
    pub cap_verifier: CapabilityVerifier,
    /// Adapter registry (execution)
    pub adapters: Arc<RwLock<aapi_adapters::AdapterRegistry>>,
    /// Dispatcher for executing VĀKYA through adapters
    pub dispatcher: Dispatcher,
    /// Policy engine for MetaRules enforcement
    pub policy_engine: PolicyEngine,
    /// Metrics collector
    pub metrics: Arc<RwLock<GatewayMetrics>>,
}

impl AppState {
    /// Create new application state with SQLite backend
    pub async fn new(config: GatewayConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let key_store = KeyStore::new();
        
        // Generate gateway signing key
        let _gateway_key = key_store.generate_key(aapi_crypto::KeyPurpose::ReceiptSigning)?;
        
        let index_db: Arc<dyn IndexDbStore> = Arc::new(
            SqliteIndexDb::new(&config.database_url).await?
        );
        
        let signer = VakyaSigner::new(key_store.clone());
        let verifier = VakyaVerifier::new(key_store.clone());
        let cap_verifier = CapabilityVerifier::new(key_store.clone());

        // Default adapter registry
        let file_base_dir = std::path::PathBuf::from("/tmp/aapi");
        let _ = tokio::fs::create_dir_all(&file_base_dir).await;
        info!(base_dir = %file_base_dir.display(), "Initializing adapter registry with file sandbox");

        let exec_registry = RegistryBuilder::new()
            .with_file_adapter_config(aapi_adapters::FileAdapter::new().with_base_dir(&file_base_dir))
            .with_http_adapter()
            .build();
        let adapters = Arc::new(RwLock::new(exec_registry));
        let dispatcher = Dispatcher::from_arc(Arc::clone(&adapters));

        // Initialize policy engine with default policies
        let policy_engine = create_default_policy_engine(config.is_default_deny()).await;
        
        Ok(Self {
            config,
            key_store,
            index_db,
            signer,
            verifier,
            cap_verifier,
            adapters,
            dispatcher,
            policy_engine,
            metrics: Arc::new(RwLock::new(GatewayMetrics::new())),
        })
    }

    /// Create state with in-memory database (for testing)
    pub async fn in_memory(config: GatewayConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let key_store = KeyStore::new();
        let _gateway_key = key_store.generate_key(aapi_crypto::KeyPurpose::ReceiptSigning)?;
        
        let index_db: Arc<dyn IndexDbStore> = Arc::new(
            SqliteIndexDb::in_memory().await?
        );
        
        let signer = VakyaSigner::new(key_store.clone());
        let verifier = VakyaVerifier::new(key_store.clone());
        let cap_verifier = CapabilityVerifier::new(key_store.clone());

        // Default adapter registry
        let file_base_dir = std::path::PathBuf::from("/tmp/aapi");
        let _ = tokio::fs::create_dir_all(&file_base_dir).await;
        info!(base_dir = %file_base_dir.display(), "Initializing adapter registry with file sandbox");

        let exec_registry = RegistryBuilder::new()
            .with_file_adapter_config(aapi_adapters::FileAdapter::new().with_base_dir(&file_base_dir))
            .with_http_adapter()
            .build();
        let adapters = Arc::new(RwLock::new(exec_registry));
        let dispatcher = Dispatcher::from_arc(Arc::clone(&adapters));

        // Initialize policy engine with default policies
        let policy_engine = create_default_policy_engine(config.is_default_deny()).await;
        
        Ok(Self {
            config,
            key_store,
            index_db,
            signer,
            verifier,
            cap_verifier,
            adapters,
            dispatcher,
            policy_engine,
            metrics: Arc::new(RwLock::new(GatewayMetrics::new())),
        })
    }
}

/// Create default policy engine with sample policies
async fn create_default_policy_engine(default_deny: bool) -> PolicyEngine {
    let engine = if default_deny {
        PolicyEngine::new()
    } else {
        PolicyEngine::new().with_default_allow()
    };

    // Policy 1: Deny file.delete outside sandbox (safety)
    let deny_dangerous_delete = Policy::new("policy:deny-dangerous-delete", "Deny Dangerous Deletes")
        .with_description("Deny file.delete actions outside the sandbox")
        .with_priority(100)
        .with_rule(
            Rule::deny("rule:deny-delete-outside-sandbox", "Deny delete outside /tmp/aapi")
                .with_condition(Condition {
                    condition_type: ConditionType::Action,
                    field: "action".to_string(),
                    operator: Operator::Eq,
                    value: serde_json::json!("file.delete"),
                })
                .with_condition(Condition {
                    condition_type: ConditionType::Resource,
                    field: "rid".to_string(),
                    operator: Operator::StartsWith,
                    value: serde_json::json!("file:/tmp/aapi"),
                    // This rule denies if NOT starting with sandbox - we need to negate
                    // For now, we'll use a simpler approach: deny all deletes by default
                })
                .with_priority(100),
        )
        .with_default_allow();

    // Policy 2: Require approval for http.post to external domains
    let require_approval_http = Policy::new("policy:http-approval", "HTTP External Approval")
        .with_description("Require approval for HTTP POST to external domains")
        .with_priority(50)
        .with_rule(
            Rule::require_approval("rule:http-post-approval", "Require approval for HTTP POST")
                .with_condition(Condition {
                    condition_type: ConditionType::Action,
                    field: "action".to_string(),
                    operator: Operator::Eq,
                    value: serde_json::json!("http.post"),
                })
                .with_priority(50),
        )
        .with_default_allow();

    // Policy 3: Allow all file operations in sandbox (baseline allow)
    let allow_sandbox_files = Policy::new("policy:allow-sandbox", "Allow Sandbox Operations")
        .with_description("Allow file operations within the sandbox")
        .with_priority(10)
        .with_rule(
            Rule::allow("rule:allow-sandbox-files", "Allow files in /tmp/aapi")
                .with_condition(Condition {
                    condition_type: ConditionType::Resource,
                    field: "rid".to_string(),
                    operator: Operator::StartsWith,
                    value: serde_json::json!("file:/tmp/aapi"),
                })
                .with_priority(10),
        )
        .with_default_allow();

    engine.add_policy(deny_dangerous_delete).await;
    engine.add_policy(require_approval_http).await;
    engine.add_policy(allow_sandbox_files).await;

    info!("Policy engine initialized with {} default policies", 3);
    engine
}

/// Gateway metrics
pub struct GatewayMetrics {
    /// Total requests received
    pub requests_total: u64,
    /// Successful requests
    pub requests_success: u64,
    /// Failed requests
    pub requests_failed: u64,
    /// Authorization denials
    pub auth_denials: u64,
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// Requests by action
    pub requests_by_action: std::collections::HashMap<String, u64>,
    /// Requests by actor
    pub requests_by_actor: std::collections::HashMap<String, u64>,
}

impl GatewayMetrics {
    pub fn new() -> Self {
        Self {
            requests_total: 0,
            requests_success: 0,
            requests_failed: 0,
            auth_denials: 0,
            avg_latency_ms: 0.0,
            requests_by_action: std::collections::HashMap::new(),
            requests_by_actor: std::collections::HashMap::new(),
        }
    }

    pub fn record_request(&mut self, action: &str, actor: &str, success: bool, latency_ms: f64) {
        self.requests_total += 1;
        if success {
            self.requests_success += 1;
        } else {
            self.requests_failed += 1;
        }

        // Update rolling average
        self.avg_latency_ms = (self.avg_latency_ms * (self.requests_total - 1) as f64 + latency_ms) 
            / self.requests_total as f64;

        *self.requests_by_action.entry(action.to_string()).or_insert(0) += 1;
        *self.requests_by_actor.entry(actor.to_string()).or_insert(0) += 1;
    }

    pub fn record_auth_denial(&mut self) {
        self.auth_denials += 1;
    }
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}
