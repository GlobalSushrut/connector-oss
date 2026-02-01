//! Adapter registry for managing and dispatching to adapters

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use aapi_core::Vakya;

use crate::error::{AdapterError, AdapterResult};
use crate::traits::{Adapter, ActionDescriptor, ExecutionContext, ExecutionResult, HealthStatus};
use crate::effect::CapturedEffect;

/// Registry for managing adapters
pub struct AdapterRegistry {
    adapters: HashMap<String, Arc<dyn Adapter>>,
    action_map: HashMap<String, String>, // action -> domain
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
            action_map: HashMap::new(),
        }
    }

    /// Register an adapter
    pub fn register<A: Adapter + 'static>(&mut self, adapter: A) {
        let domain = adapter.domain().to_string();
        let actions = adapter.supported_actions();
        
        info!(domain = %domain, actions = ?actions, "Registering adapter");

        // Map actions to domain
        for action in actions {
            self.action_map.insert(action.to_string(), domain.clone());
        }

        self.adapters.insert(domain, Arc::new(adapter));
    }

    /// Get an adapter by domain
    pub fn get(&self, domain: &str) -> Option<Arc<dyn Adapter>> {
        self.adapters.get(domain).cloned()
    }

    /// Get an adapter for an action
    pub fn get_for_action(&self, action: &str) -> Option<Arc<dyn Adapter>> {
        // First try exact match
        if let Some(domain) = self.action_map.get(action) {
            return self.adapters.get(domain).cloned();
        }

        // Try domain prefix match
        if let Some(dot_pos) = action.find('.') {
            let domain = &action[..dot_pos];
            return self.adapters.get(domain).cloned();
        }

        None
    }

    /// List all registered domains
    pub fn domains(&self) -> Vec<&str> {
        self.adapters.keys().map(|s| s.as_str()).collect()
    }

    /// List all registered actions
    pub fn actions(&self) -> Vec<&str> {
        self.action_map.keys().map(|s| s.as_str()).collect()
    }

    /// Check if an action is supported
    pub fn supports_action(&self, action: &str) -> bool {
        self.get_for_action(action).is_some()
    }

    /// Get adapter info for all registered adapters
    pub fn adapter_info(&self) -> Vec<AdapterInfo> {
        self.adapters.values().map(|a| AdapterInfo {
            domain: a.domain().to_string(),
            version: a.version().to_string(),
            actions: a.supported_actions().iter().map(|s| s.to_string()).collect(),
        }).collect()
    }

    /// Health check all adapters
    pub async fn health_check_all(&self) -> HashMap<String, HealthStatus> {
        let mut results = HashMap::new();
        
        for (domain, adapter) in &self.adapters {
            match adapter.health_check().await {
                Ok(status) => {
                    results.insert(domain.clone(), status);
                }
                Err(e) => {
                    results.insert(domain.clone(), HealthStatus::unhealthy(e.to_string()));
                }
            }
        }

        results
    }
}

/// Information about a registered adapter
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdapterInfo {
    pub domain: String,
    pub version: String,
    pub actions: Vec<String>,
}

/// Dispatcher for executing VĀKYA through adapters
pub struct Dispatcher {
    registry: Arc<RwLock<AdapterRegistry>>,
}

impl Dispatcher {
    pub fn new(registry: AdapterRegistry) -> Self {
        Self {
            registry: Arc::new(RwLock::new(registry)),
        }
    }

    pub fn from_arc(registry: Arc<RwLock<AdapterRegistry>>) -> Self {
        Self { registry }
    }

    /// Dispatch a VĀKYA to the appropriate adapter
    pub async fn dispatch(&self, vakya: &Vakya, context: &ExecutionContext) -> AdapterResult<ExecutionResult> {
        let action = &vakya.v3_kriya.action;
        
        let registry = self.registry.read().await;
        let adapter = registry.get_for_action(action)
            .ok_or_else(|| AdapterError::UnsupportedAction(format!(
                "No adapter found for action: {}",
                action
            )))?;

        debug!(action = %action, domain = %adapter.domain(), "Dispatching to adapter");

        adapter.execute(vakya, context).await
    }

    /// Rollback an effect
    pub async fn rollback(&self, effect: &CapturedEffect) -> AdapterResult<()> {
        // Determine adapter from effect target
        let domain = effect.target.split(':').next()
            .or_else(|| effect.target_type.as_deref())
            .ok_or_else(|| AdapterError::RollbackFailed(
                "Cannot determine adapter for rollback".to_string()
            ))?;

        let registry = self.registry.read().await;
        let adapter = registry.get(domain)
            .ok_or_else(|| AdapterError::RollbackFailed(format!(
                "No adapter found for domain: {}",
                domain
            )))?;

        adapter.rollback(effect).await
    }

    /// Check if an action is supported
    pub async fn supports_action(&self, action: &str) -> bool {
        let registry = self.registry.read().await;
        registry.supports_action(action)
    }

    /// Get adapter info
    pub async fn adapter_info(&self) -> Vec<AdapterInfo> {
        let registry = self.registry.read().await;
        registry.adapter_info()
    }

    /// Health check all adapters
    pub async fn health_check_all(&self) -> HashMap<String, HealthStatus> {
        let registry = self.registry.read().await;
        registry.health_check_all().await
    }
}

/// Builder for creating a pre-configured registry
pub struct RegistryBuilder {
    registry: AdapterRegistry,
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryBuilder {
    pub fn new() -> Self {
        Self {
            registry: AdapterRegistry::new(),
        }
    }

    /// Add the file adapter
    pub fn with_file_adapter(mut self) -> Self {
        self.registry.register(crate::file::FileAdapter::new());
        self
    }

    /// Add the file adapter with configuration
    pub fn with_file_adapter_config(mut self, adapter: crate::file::FileAdapter) -> Self {
        self.registry.register(adapter);
        self
    }

    /// Add the HTTP adapter
    pub fn with_http_adapter(mut self) -> Self {
        self.registry.register(crate::http::HttpAdapter::new());
        self
    }

    /// Add the HTTP adapter with configuration
    pub fn with_http_adapter_config(mut self, adapter: crate::http::HttpAdapter) -> Self {
        self.registry.register(adapter);
        self
    }

    /// Add a custom adapter
    pub fn with_adapter<A: Adapter + 'static>(mut self, adapter: A) -> Self {
        self.registry.register(adapter);
        self
    }

    /// Build the registry
    pub fn build(self) -> AdapterRegistry {
        self.registry
    }

    /// Build and wrap in a dispatcher
    pub fn build_dispatcher(self) -> Dispatcher {
        Dispatcher::new(self.registry)
    }
}

/// Create a default registry with standard adapters
pub fn default_registry() -> AdapterRegistry {
    RegistryBuilder::new()
        .with_file_adapter()
        .with_http_adapter()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileAdapter;
    use crate::http::HttpAdapter;

    #[test]
    fn test_registry_registration() {
        let mut registry = AdapterRegistry::new();
        registry.register(FileAdapter::new());
        registry.register(HttpAdapter::new());

        assert!(registry.supports_action("file.read"));
        assert!(registry.supports_action("http.get"));
        assert!(!registry.supports_action("unknown.action"));
    }

    #[test]
    fn test_registry_get_for_action() {
        let mut registry = AdapterRegistry::new();
        registry.register(FileAdapter::new());

        let adapter = registry.get_for_action("file.write");
        assert!(adapter.is_some());
        assert_eq!(adapter.unwrap().domain(), "file");
    }

    #[test]
    fn test_registry_builder() {
        let registry = RegistryBuilder::new()
            .with_file_adapter()
            .with_http_adapter()
            .build();

        assert_eq!(registry.domains().len(), 2);
    }

    #[test]
    fn test_default_registry() {
        let registry = default_registry();
        assert!(registry.supports_action("file.read"));
        assert!(registry.supports_action("http.get"));
    }

    #[tokio::test]
    async fn test_dispatcher() {
        let registry = default_registry();
        let dispatcher = Dispatcher::new(registry);

        assert!(dispatcher.supports_action("file.read").await);
        assert!(!dispatcher.supports_action("unknown.action").await);
    }
}
