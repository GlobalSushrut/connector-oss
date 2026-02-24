//! Connector — the main entry point for developers.
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! // Layer 0: 3-line agent
//! let c = Connector::new()
//!     .llm("openai", "gpt-4o", "sk-...")
//!     .build();
//! ```

use std::sync::{Arc, Mutex, RwLock};
use vac_core::kernel::MemoryKernel;
use vac_core::store::{KernelStore, InMemoryKernelStore};
use crate::types::*;
use crate::agent::AgentBuilder;
use crate::pipeline::PipelineBuilder;
use crate::security::SecurityConfig;

/// Connector — the root object. Everything starts here.
///
/// Holds a shared `MemoryKernel` via `Arc<Mutex<>>` so all agents created
/// from this Connector share the same kernel. Memories persist across
/// `agent.run()`, `agent.remember()`, and `agent.recall()` calls.
#[allow(dead_code)]
pub struct Connector {
    /// LLM configuration
    pub(crate) llm_config: Option<LlmConfig>,
    /// Memory store configuration
    pub(crate) memory_config: Option<MemoryConfig>,
    /// Compliance frameworks
    pub(crate) compliance: Vec<String>,
    /// Security configuration
    pub(crate) security: SecurityConfig,
    /// Shared memory kernel — all agents share this.
    /// Uses RwLock: reads (packet_count, audit, trust) are concurrent,
    /// writes (run, remember, recall) are exclusive.
    pub(crate) kernel: Arc<RwLock<MemoryKernel>>,
    /// Storage backend — persists kernel state across restarts
    pub(crate) store: Arc<Mutex<Box<dyn KernelStore + Send>>>,
    /// Storage connection string (for display/debug)
    pub(crate) storage_uri: Option<String>,
}

impl Clone for Connector {
    fn clone(&self) -> Self {
        Self {
            llm_config: self.llm_config.clone(),
            memory_config: self.memory_config.clone(),
            compliance: self.compliance.clone(),
            security: self.security.clone(),
            kernel: Arc::clone(&self.kernel),
            store: Arc::clone(&self.store),
            storage_uri: self.storage_uri.clone(),
        }
    }
}

impl Connector {
    /// Create a new Connector builder.
    pub fn new() -> ConnectorBuilder {
        ConnectorBuilder::default()
    }

    /// Create a pipeline builder (for multi-actor flows).
    pub fn pipeline(name: &str) -> PipelineBuilder {
        PipelineBuilder::new(name)
    }

    /// Create an agent builder (for single-agent use).
    pub fn agent(&self, name: &str) -> AgentBuilder {
        AgentBuilder::new(name, self)
    }

    /// Get the LLM config.
    pub fn llm_config(&self) -> Option<&LlmConfig> {
        self.llm_config.as_ref()
    }

    /// Convert to engine LlmConfig for actual API calls.
    pub fn engine_llm_config(&self) -> Option<connector_engine::llm::LlmConfig> {
        self.llm_config.as_ref().map(|c| {
            let mut cfg = connector_engine::llm::LlmConfig::new(&c.provider, &c.model, &c.api_key);
            if let Some(ref ep) = c.endpoint {
                cfg = cfg.with_endpoint(ep);
            }
            cfg
        })
    }

    /// Get compliance frameworks.
    pub fn compliance(&self) -> &[String] {
        &self.compliance
    }

    /// Get security config.
    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    /// Get total packet count from the shared kernel.
    pub fn packet_count(&self) -> usize {
        self.kernel.read().map(|k| k.packet_count()).unwrap_or(0)
    }

    /// Get total audit entry count from the shared kernel.
    pub fn audit_count(&self) -> usize {
        self.kernel.read().map(|k| k.audit_count()).unwrap_or(0)
    }

    /// Flush kernel state to the storage backend.
    ///
    /// Persists all packets, agents, sessions, and audit entries.
    /// Returns the number of objects written.
    pub fn save(&self) -> Result<usize, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        let mut store = self.store.lock()
            .map_err(|e| format!("Store lock poisoned: {}", e))?;
        kernel.flush_to_store(store.as_mut())
    }

    /// Load kernel state from the storage backend.
    ///
    /// Reconstructs the kernel from persisted state. Use after restart.
    pub fn load(&self) -> Result<(), String> {
        let store = self.store.lock()
            .map_err(|e| format!("Store lock poisoned: {}", e))?;
        let restored = MemoryKernel::load_from_store(store.as_ref())?;
        let mut kernel = self.kernel.write()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        *kernel = restored;
        Ok(())
    }

    /// Get the storage URI (if configured).
    pub fn storage_uri(&self) -> Option<&str> {
        self.storage_uri.as_deref()
    }

    // ─── Phase 4: Audit Durability ──────────────────────────────

    /// Verify the HMAC audit chain — checks tamper-evident hash links.
    /// Returns Ok(chain_length) or Err(description of broken link).
    pub fn verify_audit_chain(&self) -> Result<usize, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        kernel.verify_audit_chain()
    }

    /// Export audit log as JSON string.
    pub fn export_audit_json(&self) -> Result<String, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        kernel.export_audit_json()
    }

    /// Export audit log as CSV string.
    pub fn export_audit_csv(&self) -> Result<String, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        Ok(kernel.export_audit_csv())
    }

    /// Drain overflow audit entries and persist them to the storage backend.
    /// Returns the number of entries flushed.
    pub fn flush_audit_overflow(&self) -> Result<usize, String> {
        let mut kernel = self.kernel.write()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        let overflow = kernel.drain_audit_overflow();
        if overflow.is_empty() {
            return Ok(0);
        }
        let count = overflow.len();
        let mut store = self.store.lock()
            .map_err(|e| format!("Store lock poisoned: {}", e))?;
        for entry in &overflow {
            store.store_audit_entry(entry)
                .map_err(|e| format!("Failed to persist audit overflow: {}", e))?;
        }
        Ok(count)
    }
}

/// Builder for Connector.
#[derive(Default)]
pub struct ConnectorBuilder {
    llm_config: Option<LlmConfig>,
    memory_config: Option<MemoryConfig>,
    compliance: Vec<String>,
    security: SecurityConfig,
    storage: Option<String>,
}

impl ConnectorBuilder {
    /// Set the LLM provider, model, and API key.
    pub fn llm(mut self, provider: &str, model: &str, api_key: &str) -> Self {
        self.llm_config = Some(LlmConfig {
            provider: provider.to_string(),
            model: model.to_string(),
            api_key: api_key.to_string(),
            endpoint: None,
        });
        self
    }

    /// Set a custom LLM endpoint (any OpenAI-compatible API).
    pub fn llm_custom(mut self, endpoint: &str, model: &str, api_key: &str) -> Self {
        self.llm_config = Some(LlmConfig {
            provider: "custom".to_string(),
            model: model.to_string(),
            api_key: api_key.to_string(),
            endpoint: Some(endpoint.to_string()),
        });
        self
    }

    /// Read LLM config from environment variables.
    ///
    /// Reads: `CONNECTOR_LLM_PROVIDER`, `CONNECTOR_LLM_MODEL`, `CONNECTOR_LLM_API_KEY`
    pub fn llm_from_env(mut self) -> Self {
        let provider = std::env::var("CONNECTOR_LLM_PROVIDER").unwrap_or_else(|_| "openai".to_string());
        let model = std::env::var("CONNECTOR_LLM_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
        let api_key = std::env::var("CONNECTOR_LLM_API_KEY").unwrap_or_default();
        self.llm_config = Some(LlmConfig {
            provider,
            model,
            api_key,
            endpoint: std::env::var("CONNECTOR_LLM_ENDPOINT").ok(),
        });
        self
    }

    /// Set the memory store connection string.
    pub fn memory(mut self, connection: &str) -> Self {
        self.memory_config = Some(MemoryConfig {
            connection: connection.to_string(),
        });
        self
    }

    /// Set the storage backend connection string.
    ///
    /// Supported values:
    /// - `"memory"` or omit — in-memory (default, no persistence)
    /// - `"sqlite:path"` — SQLite file (Phase 13)
    /// - `"postgres://..."` — PostgreSQL (Phase 13)
    /// - `"prolly"` — Prolly tree (content-addressed)
    pub fn storage(mut self, uri: &str) -> Self {
        self.storage = Some(uri.to_string());
        self
    }

    /// Set compliance frameworks (e.g., "hipaa", "soc2", "eu_ai_act").
    pub fn compliance(mut self, frameworks: &[&str]) -> Self {
        self.compliance = frameworks.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Configure security settings.
    pub fn security<F>(mut self, f: F) -> Self
    where
        F: FnOnce(crate::security::SecurityConfigBuilder) -> crate::security::SecurityConfigBuilder,
    {
        self.security = f(crate::security::SecurityConfigBuilder::new()).build();
        self
    }

    /// Build the Connector.
    pub fn build(self) -> Connector {
        // Parse storage URI → create appropriate KernelStore backend
        let store: Box<dyn KernelStore + Send> = match self.storage.as_deref() {
            None | Some("memory") | Some("") => {
                Box::new(InMemoryKernelStore::new())
            }
            Some(uri) if uri.starts_with("redb:") => {
                let path = &uri[5..]; // strip "redb:" prefix
                match connector_engine::redb_store::RedbKernelStore::open(path) {
                    Ok(store) => Box::new(store),
                    Err(e) => {
                        eprintln!("[connector] Failed to open redb at '{}': {}. Falling back to in-memory.", path, e);
                        Box::new(InMemoryKernelStore::new())
                    }
                }
            }
            Some(uri) if uri.ends_with(".redb") => {
                // Bare file path ending in .redb — treat as redb
                match connector_engine::redb_store::RedbKernelStore::open(uri) {
                    Ok(store) => Box::new(store),
                    Err(e) => {
                        eprintln!("[connector] Failed to open redb at '{}': {}. Falling back to in-memory.", uri, e);
                        Box::new(InMemoryKernelStore::new())
                    }
                }
            }
            Some(uri) if uri.starts_with("sqlite:") => {
                // TODO: SqliteKernelStore (optional, for SQL query needs)
                eprintln!("[connector] SQLite storage not yet implemented, using in-memory. URI: {}", uri);
                Box::new(InMemoryKernelStore::new())
            }
            Some(uri) if uri.starts_with("postgres://") || uri.starts_with("postgresql://") => {
                // TODO: PostgresKernelStore
                eprintln!("[connector] Postgres storage not yet implemented, using in-memory. URI: {}", uri);
                Box::new(InMemoryKernelStore::new())
            }
            Some("prolly") => {
                // TODO: ProllyKernelStore
                eprintln!("[connector] Prolly storage not yet implemented, using in-memory.");
                Box::new(InMemoryKernelStore::new())
            }
            Some(uri) => {
                // Default: treat unknown URIs as redb file paths
                match connector_engine::redb_store::RedbKernelStore::open(uri) {
                    Ok(store) => Box::new(store),
                    Err(e) => {
                        eprintln!("[connector] Failed to open storage at '{}': {}. Falling back to in-memory.", uri, e);
                        Box::new(InMemoryKernelStore::new())
                    }
                }
            }
        };

        Connector {
            llm_config: self.llm_config,
            memory_config: self.memory_config,
            compliance: self.compliance,
            security: self.security,
            kernel: Arc::new(RwLock::new(MemoryKernel::new())),
            store: Arc::new(Mutex::new(store)),
            storage_uri: self.storage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_connector() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .build();

        assert!(c.llm_config().is_some());
        assert_eq!(c.llm_config().unwrap().provider, "openai");
        assert_eq!(c.llm_config().unwrap().model, "gpt-4o");
    }

    #[test]
    fn test_connector_with_compliance() {
        let c = Connector::new()
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            .memory("sqlite://./test.db")
            .compliance(&["hipaa", "soc2"])
            .build();

        assert_eq!(c.compliance(), &["hipaa", "soc2"]);
    }

    #[test]
    fn test_connector_with_security() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .scitt(true)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
            )
            .build();

        assert!(c.security().signing.is_some());
        assert!(c.security().scitt);
        assert_eq!(c.security().data_classification.as_deref(), Some("PHI"));
    }

    #[test]
    fn test_custom_llm() {
        let c = Connector::new()
            .llm_custom("https://my-api.com/v1", "my-model", "key-123")
            .build();

        let llm = c.llm_config().unwrap();
        assert_eq!(llm.provider, "custom");
        assert_eq!(llm.endpoint.as_deref(), Some("https://my-api.com/v1"));
    }

    #[test]
    fn test_storage_default_is_memory() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        assert!(c.storage_uri().is_none());
    }

    #[test]
    fn test_storage_explicit_memory() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage("memory")
            .build();
        assert_eq!(c.storage_uri(), Some("memory"));
    }

    #[test]
    fn test_storage_sqlite_placeholder() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage("sqlite:test.db")
            .build();
        assert_eq!(c.storage_uri(), Some("sqlite:test.db"));
    }

    #[test]
    fn test_packet_count_and_audit_count() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        assert_eq!(c.packet_count(), 0);
        assert_eq!(c.audit_count(), 0);

        // Run an agent — should increase counts
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        assert!(c.packet_count() > 0, "packet_count should increase after run");
        assert!(c.audit_count() > 0, "audit_count should increase after run");
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();

        // Run agent to populate kernel
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        let packets_before = c.packet_count();
        let audit_before = c.audit_count();
        assert!(packets_before > 0);

        // Save to store
        let written = c.save().unwrap();
        assert!(written > 0, "save() should write objects to store");

        // Simulate restart: clear kernel, then load from store
        {
            let mut kernel = c.kernel.write().unwrap();
            *kernel = MemoryKernel::new();
        }
        assert_eq!(c.packet_count(), 0, "kernel should be empty after clear");

        // Load from store
        c.load().unwrap();
        assert_eq!(c.packet_count(), packets_before,
            "load() should restore packet count: {} == {}", c.packet_count(), packets_before);
    }

    #[test]
    fn test_redb_storage_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let uri = format!("redb:{}", db_path.display());

        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage(&uri)
            .build();

        assert_eq!(c.storage_uri(), Some(uri.as_str()));

        // Run agent to populate kernel
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        let packets = c.packet_count();
        assert!(packets > 0);

        // Save to redb
        let written = c.save().unwrap();
        assert!(written > 0, "save() should write to redb");

        // Clear kernel, load back
        { *c.kernel.write().unwrap() = MemoryKernel::new(); }
        assert_eq!(c.packet_count(), 0);

        c.load().unwrap();
        assert_eq!(c.packet_count(), packets,
            "redb load should restore {} packets", packets);
    }

    #[test]
    fn test_redb_persistence_across_connectors() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("shared.redb");
        let uri = format!("redb:{}", db_path.display());

        // Connector 1: run agent, save
        {
            let c1 = Connector::new()
                .llm("openai", "gpt-4o", "sk-test")
                .storage(&uri)
                .build();
            let _ = c1.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
            assert!(c1.packet_count() > 0);
            c1.save().unwrap();
        }

        // Connector 2: new instance, same file, load and verify
        {
            let c2 = Connector::new()
                .llm("openai", "gpt-4o", "sk-test")
                .storage(&uri)
                .build();
            assert_eq!(c2.packet_count(), 0, "fresh connector starts empty");

            c2.load().unwrap();
            assert!(c2.packet_count() > 0,
                "c2 should recover packets from c1's save");
        }
    }

    #[test]
    fn test_connector_verify_audit_chain() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        let _ = c.agent("bot").instructions("Hi").run("World", "user:a").unwrap();

        let result = c.verify_audit_chain();
        assert!(result.is_ok(), "Audit chain should be valid: {:?}", result);
        let chain_len = result.unwrap();
        assert!(chain_len >= 4, "Should have multiple audit entries, got {}", chain_len);
    }

    #[test]
    fn test_connector_export_audit_json() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();

        let json = c.export_audit_json().unwrap();
        assert!(json.starts_with('['));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.as_array().unwrap().len() >= 2);
    }

    #[test]
    fn test_connector_export_audit_csv() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();

        let csv = c.export_audit_csv().unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines.len() >= 3, "CSV should have header + rows");
        assert!(lines[0].contains("audit_id"));
    }

    #[test]
    fn test_phase6_aapi_data_in_pipeline_output() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .build();

        let output = c.agent("bot").instructions("Hi").run("Hello world", "user:alice").unwrap();

        // Phase 6: PipelineOutput should have real AAPI action records
        // register + start + 2 remember calls = at least 2 action records (register + 2 writes)
        assert!(output.aapi.action_records >= 2,
            "Should have action records from ActionEngine, got {}", output.aapi.action_records);

        // Vakya count should be > 0 (AutoVakya constructs one per memory write)
        assert!(output.aapi.vakya_count >= 1,
            "Should have Vakya envelopes, got {}", output.aapi.vakya_count);

        // Authorized count should be > 0
        assert!(output.aapi.authorized >= 1,
            "Should have authorized actions, got {}", output.aapi.authorized);
    }

    #[test]
    fn test_phase5_security_tags_flow_through() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .scitt(true)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
                .max_delegation_depth(3)
                .require_mfa(true)
            )
            .build();

        // Run agent — security tags should be applied to all packets
        let _ = c.agent("doctor").instructions("Medical AI").run("Patient has fever", "user:patient1").unwrap();

        // Verify audit chain is valid (HMAC signing is always on)
        let chain = c.verify_audit_chain().unwrap();
        assert!(chain >= 2, "Should have audit entries with HMAC chain");

        // Verify security config is stored
        assert!(c.security().signing.is_some());
        assert!(c.security().scitt);
        assert_eq!(c.security().data_classification.as_deref(), Some("PHI"));
        assert_eq!(c.security().jurisdiction.as_deref(), Some("US"));
        assert_eq!(c.security().retention_days, 2555);
        assert_eq!(c.security().max_delegation_depth, 3);
        assert!(c.security().require_mfa);
    }

    #[test]
    fn test_redb_file_extension_auto_detect() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("auto.redb");

        // Passing a bare .redb path should auto-detect redb backend
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage(&db_path.display().to_string())
            .build();

        let _ = c.agent("bot").instructions("Hi").run("Test", "user:a").unwrap();
        let written = c.save().unwrap();
        assert!(written > 0, "auto-detected redb should persist");
    }
}
