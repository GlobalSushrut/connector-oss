//! # vac-ffi — Thin PyO3 Bindings
//!
//! Exposes the Connector API to Python via PyO3.
//! The kernel lives INSIDE the Connector and persists across all agent calls.
//!
//! ```python
//! from vac_ffi import Connector
//!
//! c = Connector("deepseek", "deepseek-chat", "sk-...")
//! agent = c.agent("bot", "You are helpful")
//! result = agent.run("Hello!", "user:alice")
//! print(result.text)
//! print(result.trust)       # varies based on kernel state
//! print(c.packet_count())   # grows with each call
//! print(c.audit_count())    # every operation audited
//! ```

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::sync::{Arc, Mutex};
use vac_core::kernel::{MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue};
use vac_core::types::{MemoryKernelOp, PacketType, Source, SourceKind, MemPacket, OpOutcome};
use connector_engine::llm::LlmClient;
use connector_engine::claims::{Claim, ClaimVerifier, Evidence, SupportLevel};
use connector_engine::grounding::GroundingTable;
use connector_engine::memory::{MemoryCoordinator, KnowledgeCoordinator, PacketSummary};
use connector_engine::rag::RagEngine;
use connector_engine::judgment::{JudgmentEngine, JudgmentConfig};
use connector_engine::trust::TrustComputer;
use connector_engine::perception::{PerceptionEngine, ObservationConfig};
use connector_engine::knowledge::KnowledgeEngine;
use connector_engine::logic::{LogicEngine, ReasoningChain};
use connector_engine::binding::BindingEngine;
use connector_engine::aapi::{ActionEngine, PolicyRule, PolicyEffect, ComplianceConfig};
use connector_engine::kernel_ops::KernelOps;
use vac_core::knot::{KnotEngine, KnotQuery};

// ── Helpers ──────────────────────────────────────────────────────

fn make_packet(content: &str, user: &str, pipeline: &str, ptype: PacketType) -> MemPacket {
    MemPacket::new(
        ptype,
        serde_json::json!({"text": content}),
        cid::Cid::default(),
        user.to_string(),
        pipeline.to_string(),
        Source { kind: SourceKind::User, principal_id: user.to_string() },
        chrono::Utc::now().timestamp_millis(),
    )
}

fn register_and_start(
    kernel: &mut MemoryKernel,
    name: &str,
    namespace: &str,
    model: Option<String>,
) -> Result<String, String> {
    let result = kernel.dispatch(SyscallRequest {
        agent_pid: "system".to_string(),
        operation: MemoryKernelOp::AgentRegister,
        payload: SyscallPayload::AgentRegister {
            agent_name: name.to_string(),
            namespace: namespace.to_string(),
            role: Some("agent".to_string()),
            model,
            framework: Some("connector".to_string()),
        },
        reason: Some(format!("Agent '{}' registration", name)),
        vakya_id: None,
    });
    let pid = match result.value {
        SyscallValue::AgentPid(p) => p,
        _ => return Err(format!("Failed to register agent '{}'", name)),
    };
    kernel.dispatch(SyscallRequest {
        agent_pid: pid.clone(),
        operation: MemoryKernelOp::AgentStart,
        payload: SyscallPayload::Empty,
        reason: None,
        vakya_id: None,
    });
    Ok(pid)
}

fn write_mem(
    kernel: &mut MemoryKernel,
    pid: &str,
    content: &str,
    user: &str,
    pipe: &str,
    ptype: PacketType,
) -> Option<cid::Cid> {
    let r = kernel.dispatch(SyscallRequest {
        agent_pid: pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite {
            packet: make_packet(content, user, pipe, ptype),
        },
        reason: None,
        vakya_id: None,
    });
    match r.value {
        SyscallValue::Cid(c) => Some(c),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════
// Connector — holds a PERSISTENT kernel
// ═══════════════════════════════════════════════════════════════

#[pyclass]
#[derive(Clone)]
struct Connector {
    inner: connector_api::Connector,
    kernel: Arc<Mutex<MemoryKernel>>,
    grounding: Arc<Mutex<Option<GroundingTable>>>,
    knot: Arc<Mutex<KnotEngine>>,
    binding: Arc<Mutex<BindingEngine>>,
    aapi: Arc<Mutex<ActionEngine>>,
    engine_store: Arc<Mutex<Box<dyn connector_engine::engine_store::EngineStore + Send>>>,
    storage_layout: connector_engine::storage_zone::StorageLayout,
}

impl Connector {
    /// Internal helper: build a Connector from a parsed ConnectorConfig.
    fn _from_connector_config(cfg: connector_api::config::ConnectorConfig) -> Self {
        let g = &cfg.connector;
        let builder = match (g.endpoint.as_deref(), g.api_key.as_deref(), g.provider.as_deref()) {
            (Some(ep), Some(key), _) => {
                connector_api::Connector::new()
                    .llm_custom(ep, g.model.as_deref().unwrap_or("gpt-4o"), key)
            }
            (None, Some(key), Some(prov)) => {
                connector_api::Connector::new()
                    .llm(prov, g.model.as_deref().unwrap_or("gpt-4o"), key)
            }
            _ => connector_api::Connector::new().llm_from_env(),
        };
        let builder = if let Some(ref uri) = g.storage {
            builder.storage(uri)
        } else {
            builder
        };
        let builder = if !g.comply.is_empty() {
            let refs: Vec<&str> = g.comply.iter().map(|s| s.as_str()).collect();
            builder.compliance(&refs)
        } else {
            builder
        };
        Self::_build(builder.build())
    }

    fn _build(inner: connector_api::Connector) -> Self {
        let es: Box<dyn connector_engine::engine_store::EngineStore + Send> =
            Box::new(connector_engine::engine_store::InMemoryEngineStore::new());
        Self {
            inner,
            kernel: Arc::new(Mutex::new(MemoryKernel::new())),
            grounding: Arc::new(Mutex::new(None)),
            knot: Arc::new(Mutex::new(KnotEngine::new())),
            binding: Arc::new(Mutex::new(BindingEngine::new())),
            aapi: Arc::new(Mutex::new(ActionEngine::new())),
            engine_store: Arc::new(Mutex::new(es)),
            storage_layout: connector_engine::storage_zone::StorageLayout::default_for_cell("cell_local"),
        }
    }
}

#[pymethods]
impl Connector {
    #[new]
    #[pyo3(signature = (provider, model, api_key, endpoint=None))]
    fn new(provider: &str, model: &str, api_key: &str, endpoint: Option<&str>) -> Self {
        let builder = if let Some(ep) = endpoint {
            connector_api::Connector::new().llm_custom(ep, model, api_key)
        } else {
            connector_api::Connector::new().llm(provider, model, api_key)
        };
        Self::_build(builder.build())
    }

    #[staticmethod]
    fn from_env() -> Self {
        Self::_build(connector_api::Connector::new().llm_from_env().build())
    }

    #[staticmethod]
    fn custom(endpoint: &str, model: &str, token: &str) -> Self {
        Self::_build(connector_api::Connector::new().llm_custom(endpoint, model, token).build())
    }

    /// Load a Connector from a connector.yaml file path.
    /// Supports ${ENV_VAR} interpolation in all string values.
    ///
    /// ```python
    /// c = Connector.from_config("connector.yaml")
    /// ```
    #[staticmethod]
    fn from_config(path: &str) -> PyResult<Self> {
        let cfg = connector_api::config::load_config(path)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self::_from_connector_config(cfg))
    }

    /// Load a Connector from a YAML string.
    /// Useful for testing or in-memory configs.
    ///
    /// ```python
    /// yaml = "connector:\n  provider: openai\n  model: gpt-4o\n  api_key: sk-test\n"
    /// c = Connector.from_config_str(yaml)
    /// ```
    #[staticmethod]
    fn from_config_str(yaml: &str) -> PyResult<Self> {
        let cfg = connector_api::config::load_config_str(yaml)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self::_from_connector_config(cfg))
    }

    fn agent(&self, name: &str, instructions: &str) -> Agent {
        Agent {
            connector: self.inner.clone(),
            kernel: self.kernel.clone(),
            name: name.to_string(),
            instructions: instructions.to_string(),
            compliance: Vec::new(),
            pid: None,
        }
    }

    fn pipeline(&self, name: &str) -> Pipeline {
        Pipeline {
            connector: self.inner.clone(),
            kernel: self.kernel.clone(),
            name: name.to_string(),
            agents: Vec::new(),
            route: None,
            compliance: Vec::new(),
        }
    }

    // ── Kernel introspection ─────────────────────────────────────

    /// Total packets in the kernel across all namespaces.
    fn packet_count(&self) -> usize {
        self.kernel.lock().unwrap().packet_count()
    }

    /// Packets in a specific namespace.
    fn namespace_packet_count(&self, namespace: &str) -> usize {
        self.kernel.lock().unwrap().packets_in_namespace(namespace).len()
    }

    /// Total audit log entries.
    fn audit_count(&self) -> usize {
        self.kernel.lock().unwrap().audit_log().len()
    }

    /// Number of registered agents.
    fn agent_count(&self) -> usize {
        self.kernel.lock().unwrap().agents().len()
    }

    /// Count denied operations in audit log.
    fn denied_count(&self) -> usize {
        self.kernel.lock().unwrap().audit_log().iter()
            .filter(|e| e.outcome == OpOutcome::Denied)
            .count()
    }

    /// Try to read a packet by CID from a specific agent's perspective.
    /// Returns "denied" if namespace isolation blocks it, or the packet text.
    fn try_read(&self, agent_pid: &str, packet_cid_str: &str) -> String {
        let mut k = self.kernel.lock().unwrap();
        // Parse CID from the stored string
        let cid: cid::Cid = match packet_cid_str.parse() {
            Ok(c) => c,
            Err(_) => return format!("error:invalid_cid:{}", packet_cid_str),
        };
        let r = k.dispatch(SyscallRequest {
            agent_pid: agent_pid.to_string(),
            operation: MemoryKernelOp::MemRead,
            payload: SyscallPayload::MemRead { packet_cid: cid },
            reason: Some("cross-namespace read attempt".to_string()),
            vakya_id: None,
        });
        match r.outcome {
            OpOutcome::Denied => format!("DENIED:{}", r.audit_entry.error.unwrap_or_default()),
            OpOutcome::Success => {
                match r.value {
                    SyscallValue::Packet(p) => {
                        p.content.payload.get("text")
                            .and_then(|v| v.as_str())
                            .unwrap_or("[binary]")
                            .to_string()
                    }
                    _ => "ok".to_string(),
                }
            }
            _ => format!("FAILED:{}", r.audit_entry.error.unwrap_or_default()),
        }
    }

    /// Grant read access from one agent's namespace to another agent.
    fn grant_access(&self, owner_pid: &str, namespace: &str, grantee_pid: &str) -> String {
        let mut k = self.kernel.lock().unwrap();
        let r = k.dispatch(SyscallRequest {
            agent_pid: owner_pid.to_string(),
            operation: MemoryKernelOp::AccessGrant,
            payload: SyscallPayload::AccessGrant {
                target_namespace: namespace.to_string(),
                grantee_pid: grantee_pid.to_string(),
                read: true,
                write: false,
                expires_at: None,
            },
            reason: Some("explicit access grant".to_string()),
            vakya_id: None,
        });
        format!("{:?}", r.outcome)
    }

    /// Run kernel integrity check. Returns (ok, error_count).
    fn integrity_check(&self) -> (bool, usize) {
        let mut k = self.kernel.lock().unwrap();
        // Need a registered agent PID — use first registered agent or register a system agent
        let pid = k.agents().keys().next().cloned().unwrap_or_else(|| {
            let r = k.dispatch(SyscallRequest {
                agent_pid: "system".to_string(),
                operation: MemoryKernelOp::AgentRegister,
                payload: SyscallPayload::AgentRegister {
                    agent_name: "system".to_string(),
                    namespace: "ns:system".to_string(),
                    role: Some("admin".to_string()),
                    model: None,
                    framework: Some("connector".to_string()),
                },
                reason: Some("system agent for integrity check".to_string()),
                vakya_id: None,
            });
            match r.value {
                SyscallValue::AgentPid(p) => {
                    k.dispatch(SyscallRequest {
                        agent_pid: p.clone(),
                        operation: MemoryKernelOp::AgentStart,
                        payload: SyscallPayload::Empty,
                        reason: None,
                        vakya_id: None,
                    });
                    p
                }
                _ => "pid:000001".to_string(),
            }
        });
        let r = k.dispatch(SyscallRequest {
            agent_pid: pid,
            operation: MemoryKernelOp::IntegrityCheck,
            payload: SyscallPayload::IntegrityCheck,
            reason: None,
            vakya_id: None,
        });
        match r.value {
            SyscallValue::Bool(ok) => (ok, 0),
            SyscallValue::Count(n) => (n == 0, n as usize),
            _ => (r.outcome == OpOutcome::Success, 0),
        }
    }

    /// Write a raw packet to a namespace (for stress testing).
    /// Returns the CID string.
    fn write_packet(&self, agent_pid: &str, content: &str, user: &str, pipe: &str) -> String {
        let mut k = self.kernel.lock().unwrap();
        let r = k.dispatch(SyscallRequest {
            agent_pid: agent_pid.to_string(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite {
                packet: make_packet(content, user, pipe, PacketType::Extraction),
            },
            reason: None,
            vakya_id: None,
        });
        match r.value {
            SyscallValue::Cid(c) => c.to_string(),
            _ => "error".to_string(),
        }
    }

    /// Register an agent directly and return its PID.
    fn register_agent(&self, name: &str) -> PyResult<String> {
        let mut k = self.kernel.lock().unwrap();
        register_and_start(&mut k, name, &format!("ns:{}", name), None)
            .map_err(PyRuntimeError::new_err)
    }

    /// Get trust score breakdown as dict.
    fn trust_breakdown(&self) -> std::collections::HashMap<String, u32> {
        let k = self.kernel.lock().unwrap();
        let trust = TrustComputer::compute(&k);
        let mut m = std::collections::HashMap::new();
        m.insert("total".into(), trust.score);
        m.insert("memory_integrity".into(), trust.dimensions.memory_integrity);
        m.insert("audit_completeness".into(), trust.dimensions.audit_completeness);
        m.insert("authorization_coverage".into(), trust.dimensions.authorization_coverage);
        m.insert("decision_provenance".into(), trust.dimensions.decision_provenance);
        m.insert("operational_health".into(), trust.dimensions.operational_health);
        m
    }

    // ── Grounding Table ────────────────────────────────────────────

    /// Load a grounding table from a JSON file.
    fn load_grounding_table(&self, path: &str) -> PyResult<()> {
        let table = GroundingTable::from_file(path)
            .map_err(PyRuntimeError::new_err)?;
        *self.grounding.lock().unwrap() = Some(table);
        Ok(())
    }

    /// Load a grounding table from a JSON string.
    fn load_grounding_json(&self, json_str: &str) -> PyResult<()> {
        let table = GroundingTable::from_json(json_str)
            .map_err(PyRuntimeError::new_err)?;
        *self.grounding.lock().unwrap() = Some(table);
        Ok(())
    }

    /// Lookup a code from the grounding table. Returns {code, desc, system} or None.
    fn lookup_code(&self, category: &str, term: &str) -> Option<std::collections::HashMap<String, String>> {
        let g = self.grounding.lock().unwrap();
        g.as_ref().and_then(|table| {
            table.lookup_fuzzy(category, term).map(|entry| {
                let mut m = std::collections::HashMap::new();
                m.insert("code".into(), entry.code.clone());
                m.insert("desc".into(), entry.desc.clone());
                m.insert("system".into(), entry.system.clone());
                m
            })
        })
    }

    // ── Claim Verification ─────────────────────────────────────────

    /// Verify a list of claims against source text.
    ///
    /// Each claim is a dict: {item, category, quote, support, code?, code_desc?}
    /// source_text: the original text to verify against
    /// source_cid: the CID of the source packet
    ///
    /// Returns a dict with: confirmed (list), rejected (list), needs_review (list),
    /// validity_ratio (float), warnings (list of strings)
    fn verify_claims(
        &self,
        claims_dicts: Vec<std::collections::HashMap<String, String>>,
        source_text: &str,
        source_cid: &str,
    ) -> std::collections::HashMap<String, PyObject> {
        Python::with_gil(|py| {
            // Convert Python dicts to Rust Claims, applying grounding table
            let grounding = self.grounding.lock().unwrap();
            let claims: Vec<Claim> = claims_dicts.iter().map(|d| {
                let item = d.get("item").cloned().unwrap_or_default();
                let category = d.get("category").cloned().unwrap_or("conditions".into());
                let quote = d.get("quote").cloned().unwrap_or_default();
                let support_str = d.get("support").cloned().unwrap_or("absent".into());

                // Lookup code from grounding table if not provided
                let (code, code_desc) = if let Some(c) = d.get("code") {
                    (Some(c.clone()), d.get("code_desc").cloned())
                } else if let Some(ref table) = *grounding {
                    match table.lookup_fuzzy(&category, &item) {
                        Some(entry) => (Some(entry.code.clone()), Some(entry.desc.clone())),
                        None => (None, None),
                    }
                } else {
                    (None, None)
                };

                Claim {
                    item,
                    category,
                    evidence: Evidence {
                        source_cid: source_cid.to_string(),
                        field_path: d.get("field_path").cloned(),
                        quote,
                        support: SupportLevel::from_str(&support_str),
                    },
                    code,
                    code_desc,
                }
            }).collect();

            let claim_set = ClaimVerifier::verify(&claims, source_text, source_cid);

            // Build result dict
            let mut result = std::collections::HashMap::new();

            let confirmed: Vec<std::collections::HashMap<String, String>> = claim_set.confirmed().iter().map(|r| {
                let mut m = std::collections::HashMap::new();
                m.insert("item".into(), r.claim.item.clone());
                m.insert("code".into(), r.claim.code.clone().unwrap_or_default());
                m.insert("code_desc".into(), r.claim.code_desc.clone().unwrap_or_default());
                m.insert("quote".into(), r.claim.evidence.quote.clone());
                m.insert("reason".into(), r.reason.clone());
                m
            }).collect();

            let rejected: Vec<std::collections::HashMap<String, String>> = claim_set.rejected().iter().map(|r| {
                let mut m = std::collections::HashMap::new();
                m.insert("item".into(), r.claim.item.clone());
                m.insert("code".into(), r.claim.code.clone().unwrap_or_default());
                m.insert("outcome".into(), r.outcome.to_string());
                m.insert("reason".into(), r.reason.clone());
                m
            }).collect();

            let warnings: Vec<String> = claim_set.warnings();

            result.insert("confirmed".into(), confirmed.into_py(py));
            result.insert("rejected".into(), rejected.into_py(py));
            result.insert("confirmed_count".into(), claim_set.confirmed_count().into_py(py));
            result.insert("rejected_count".into(), claim_set.rejected_count().into_py(py));
            result.insert("needs_review_count".into(), claim_set.needs_review_count().into_py(py));
            result.insert("total".into(), claim_set.total().into_py(py));
            result.insert("validity_ratio".into(), claim_set.validity_ratio().into_py(py));
            result.insert("warnings".into(), warnings.into_py(py));

            // Compute trust with claims
            let k = self.kernel.lock().unwrap();
            let trust = TrustComputer::compute_with_claims(&k, &claim_set);
            result.insert("trust_score".into(), trust.score.into_py(py));
            result.insert("trust_grade".into(), trust.grade.into_py(py));
            result.insert("claim_validity".into(), trust.dimensions.claim_validity.unwrap_or(20).into_py(py));

            result
        })
    }

    // ── Session Management ────────────────────────────────────────

    /// Create a session for an agent. Returns session_id.
    #[pyo3(signature = (agent_pid, label=None))]
    fn create_session(&self, agent_pid: &str, label: Option<&str>) -> PyResult<String> {
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::create_session(&mut k, agent_pid, label)
            .map_err(PyRuntimeError::new_err)
    }

    /// Close a session.
    fn close_session(&self, agent_pid: &str, session_id: &str) -> PyResult<()> {
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::close_session(&mut k, agent_pid, session_id)
            .map_err(PyRuntimeError::new_err)
    }

    // ── Memory Write/Read ───────────────────────────────────────

    /// Write a memory packet with entities and tags. Returns CID string.
    #[pyo3(signature = (agent_pid, content, user, pipeline, packet_type="input", session_id=None, entities=None, tags=None))]
    fn memory_write(
        &self, agent_pid: &str, content: &str, user: &str, pipeline: &str,
        packet_type: &str, session_id: Option<&str>,
        entities: Option<Vec<String>>, tags: Option<Vec<String>>,
    ) -> PyResult<String> {
        let ptype = match packet_type {
            "input" => PacketType::Input,
            "llm_raw" => PacketType::LlmRaw,
            "extraction" => PacketType::Extraction,
            "decision" => PacketType::Decision,
            "action" => PacketType::Action,
            "tool_call" => PacketType::ToolCall,
            "tool_result" => PacketType::ToolResult,
            "feedback" => PacketType::Feedback,
            "contradiction" => PacketType::Contradiction,
            "state_change" => PacketType::StateChange,
            _ => PacketType::Input,
        };
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::write(&mut k, agent_pid, content, user, pipeline, ptype, session_id, entities.unwrap_or_default(), tags.unwrap_or_default())
            .map(|c| c.to_string())
            .map_err(PyRuntimeError::new_err)
    }

    /// Recall a packet by CID string. Returns text content.
    fn memory_recall(&self, agent_pid: &str, cid_str: &str) -> PyResult<String> {
        let c: cid::Cid = cid_str.parse().map_err(|e: cid::Error| PyRuntimeError::new_err(e.to_string()))?;
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::recall(&mut k, agent_pid, &c)
            .map_err(PyRuntimeError::new_err)
    }

    // ── Search ──────────────────────────────────────────────────

    /// Search packets in a namespace. Returns list of dicts.
    #[pyo3(signature = (namespace, limit=50))]
    fn search_namespace(&self, namespace: &str, limit: usize) -> Vec<std::collections::HashMap<String, PyObject>> {
        let k = self.kernel.lock().unwrap();
        let results = MemoryCoordinator::search_namespace(&k, namespace, limit);
        Python::with_gil(|py| {
            results.iter().map(|s| summary_to_dict(s, py)).collect()
        })
    }

    /// Search packets in a session. Returns list of dicts.
    #[pyo3(signature = (session_id, limit=50))]
    fn search_session(&self, session_id: &str, limit: usize) -> Vec<std::collections::HashMap<String, PyObject>> {
        let k = self.kernel.lock().unwrap();
        let results = MemoryCoordinator::search_session(&k, session_id, limit);
        Python::with_gil(|py| {
            results.iter().map(|s| summary_to_dict(s, py)).collect()
        })
    }

    // ── Memory Tiers ────────────────────────────────────────────

    /// Promote a packet to higher tier (e.g. Warm → Hot).
    fn memory_promote(&self, agent_pid: &str, cid_str: &str) -> PyResult<()> {
        let c: cid::Cid = cid_str.parse().map_err(|e: cid::Error| PyRuntimeError::new_err(e.to_string()))?;
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::promote(&mut k, agent_pid, &c)
            .map_err(PyRuntimeError::new_err)
    }

    /// Demote a packet to lower tier (e.g. Hot → Cold).
    fn memory_demote(&self, agent_pid: &str, cid_str: &str) -> PyResult<()> {
        let c: cid::Cid = cid_str.parse().map_err(|e: cid::Error| PyRuntimeError::new_err(e.to_string()))?;
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::demote(&mut k, agent_pid, &c)
            .map_err(PyRuntimeError::new_err)
    }

    /// Seal a packet (make immutable).
    fn memory_seal(&self, agent_pid: &str, cid_str: &str) -> PyResult<()> {
        let c: cid::Cid = cid_str.parse().map_err(|e: cid::Error| PyRuntimeError::new_err(e.to_string()))?;
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::seal(&mut k, agent_pid, &c)
            .map_err(PyRuntimeError::new_err)
    }

    // ── Access Control ──────────────────────────────────────────

    /// Grant read access on a namespace to another agent.
    fn grant_read(&self, owner_pid: &str, namespace: &str, grantee_pid: &str) -> PyResult<()> {
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::grant_read(&mut k, owner_pid, namespace, grantee_pid)
            .map_err(PyRuntimeError::new_err)
    }

    /// Revoke access on a namespace from another agent.
    fn revoke_access(&self, owner_pid: &str, namespace: &str, grantee_pid: &str) -> PyResult<()> {
        let mut k = self.kernel.lock().unwrap();
        MemoryCoordinator::revoke(&mut k, owner_pid, namespace, grantee_pid)
            .map_err(PyRuntimeError::new_err)
    }

    // ── Knowledge Graph (KnotEngine) ────────────────────────────

    /// Ingest all packets from a namespace into the knowledge graph.
    fn knowledge_ingest(&self, namespace: &str) {
        let k = self.kernel.lock().unwrap();
        let mut knot = self.knot.lock().unwrap();
        let packets: Vec<MemPacket> = k.packets_in_namespace(namespace).into_iter().cloned().collect();
        if !packets.is_empty() {
            knot.ingest_packets(&packets, 0);
        }
    }

    /// Add an entity to the knowledge graph.
    #[pyo3(signature = (entity_id, entity_type=None, tags=None))]
    fn knowledge_add_entity(&self, entity_id: &str, entity_type: Option<&str>, tags: Option<Vec<String>>) {
        let mut knot = self.knot.lock().unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let t = tags.unwrap_or_default();
        knot.upsert_node(entity_id, entity_type, std::collections::BTreeMap::new(), &t, now, 0, None);
    }

    /// Add a relationship edge to the knowledge graph.
    fn knowledge_add_edge(&self, from: &str, to: &str, relation: &str, weight: f64) {
        let mut knot = self.knot.lock().unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        knot.upsert_edge(from, to, relation, weight, now, 0, None);
    }

    /// Query the knowledge graph. Returns list of {id, score, channels}.
    #[pyo3(signature = (entities=None, keywords=None, limit=20))]
    fn knowledge_query(
        &self, entities: Option<Vec<String>>, keywords: Option<Vec<String>>, limit: usize,
    ) -> Vec<std::collections::HashMap<String, PyObject>> {
        let knot = self.knot.lock().unwrap();
        let query = KnotQuery {
            entities: entities.unwrap_or_default(),
            keywords: keywords.unwrap_or_default(),
            time_range: None, semantic_query: None,
            limit, token_budget: 4096,
            min_trust_tier: None, rrf_k: 60.0,
        };
        let results = knot.query(&query);
        Python::with_gil(|py| {
            results.iter().map(|r| {
                let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
                m.insert("id".into(), r.id.clone().into_py(py));
                m.insert("score".into(), r.rrf_score.into_py(py));
                m.insert("channels".into(), r.channels.iter().map(|c| c.to_string()).collect::<Vec<_>>().into_py(py));
                m.insert("packet_cids".into(), r.packet_cids.iter().map(|c| c.to_string()).collect::<Vec<_>>().into_py(py));
                m
            }).collect()
        })
    }

    /// Get entity count in knowledge graph.
    fn knowledge_entity_count(&self) -> usize {
        self.knot.lock().unwrap().node_count()
    }

    /// Get all entity IDs in knowledge graph.
    fn knowledge_entity_ids(&self) -> Vec<String> {
        self.knot.lock().unwrap().nodes().keys().cloned().collect()
    }

    /// Get neighbors of an entity in the knowledge graph.
    fn knowledge_neighbors(&self, entity_id: &str) -> Vec<String> {
        self.knot.lock().unwrap().neighbors(entity_id).into_iter().map(|s| s.to_string()).collect()
    }

    // ── RAG (Retrieval-Augmented Generation) ────────────────────

    /// Retrieve grounded context from kernel memory for LLM prompt injection.
    /// Returns dict with: facts (list), tokens_used, source_cids, prompt_context (str).
    #[pyo3(signature = (entities=None, keywords=None, token_budget=4096, max_facts=20))]
    fn rag_retrieve(
        &self, entities: Option<Vec<String>>, keywords: Option<Vec<String>>,
        token_budget: usize, max_facts: usize,
    ) -> std::collections::HashMap<String, PyObject> {
        let knot = self.knot.lock().unwrap();
        let k = self.kernel.lock().unwrap();
        let grounding = self.grounding.lock().unwrap();
        let rag = RagEngine::new().with_budget(token_budget).with_max_facts(max_facts);
        let ent = entities.unwrap_or_default();
        let kw = keywords.unwrap_or_default();
        let ctx = rag.retrieve(&knot, &k, &ent, &kw, None, grounding.as_ref());

        // Compute prompt context before moving fields
        let prompt_ctx = ctx.to_prompt_context();
        Python::with_gil(|py| {
            let mut result: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            let facts: Vec<std::collections::HashMap<String, PyObject>> = ctx.facts.iter().map(|f| {
                let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
                m.insert("text".into(), f.text.clone().into_py(py));
                m.insert("source_cid".into(), f.source_cid.clone().into_py(py));
                m.insert("entity_id".into(), f.entity_id.clone().into_py(py));
                m.insert("relevance_score".into(), f.relevance_score.into_py(py));
                m.insert("tier".into(), f.tier.clone().into_py(py));
                m.insert("namespace".into(), f.namespace.clone().into_py(py));
                if let Some(ref c) = f.grounded_code { m.insert("grounded_code".into(), c.clone().into_py(py)); }
                if let Some(ref d) = f.grounded_desc { m.insert("grounded_desc".into(), d.clone().into_py(py)); }
                m
            }).collect();
            result.insert("facts".into(), facts.into_py(py));
            result.insert("facts_included".into(), ctx.facts_included.into_py(py));
            result.insert("total_retrieved".into(), ctx.total_retrieved.into_py(py));
            result.insert("tokens_used".into(), ctx.tokens_used.into_py(py));
            result.insert("source_cids".into(), ctx.source_cids.into_py(py));
            result.insert("entities".into(), ctx.entities.into_py(py));
            result.insert("channels_used".into(), ctx.channels_used.into_py(py));
            result.insert("warnings".into(), ctx.warnings.into_py(py));
            result.insert("prompt_context".into(), prompt_ctx.into_py(py));
            result
        })
    }

    // ── Advanced Judgment ────────────────────────────────────────

    /// Compute advanced 8-dimension judgment score.
    /// Returns dict with: score, grade, explanation, dimensions (dict), warnings.
    #[pyo3(signature = (profile="default"))]
    fn judgment(&self, profile: &str) -> std::collections::HashMap<String, PyObject> {
        let k = self.kernel.lock().unwrap();
        let config = match profile {
            "medical" => JudgmentConfig::medical(),
            "financial" => JudgmentConfig::financial(),
            _ => JudgmentConfig::default(),
        };
        let j = JudgmentEngine::judge(&k, None, &config);
        Python::with_gil(|py| judgment_to_dict(&j, py))
    }

    /// Compute judgment with claim verification results.
    /// claims_dicts: list of {item, category, quote, support, code?, code_desc?}
    /// source_text: original text to verify against
    /// source_cid: CID of source packet
    #[pyo3(signature = (claims_dicts, source_text, source_cid, profile="default"))]
    fn judgment_with_claims(
        &self,
        claims_dicts: Vec<std::collections::HashMap<String, String>>,
        source_text: &str, source_cid: &str,
        profile: &str,
    ) -> std::collections::HashMap<String, PyObject> {
        let grounding = self.grounding.lock().unwrap();
        let claims: Vec<Claim> = claims_dicts.iter().map(|d| {
            let item = d.get("item").cloned().unwrap_or_default();
            let category = d.get("category").cloned().unwrap_or("conditions".into());
            let quote = d.get("quote").cloned().unwrap_or_default();
            let support_str = d.get("support").cloned().unwrap_or("absent".into());
            let (code, code_desc) = if let Some(c) = d.get("code") {
                (Some(c.clone()), d.get("code_desc").cloned())
            } else if let Some(ref table) = *grounding {
                match table.lookup_fuzzy(&category, &item) {
                    Some(entry) => (Some(entry.code.clone()), Some(entry.desc.clone())),
                    None => (None, None),
                }
            } else { (None, None) };
            Claim {
                item, category,
                evidence: Evidence {
                    source_cid: source_cid.to_string(),
                    field_path: d.get("field_path").cloned(),
                    quote, support: SupportLevel::from_str(&support_str),
                },
                code, code_desc,
            }
        }).collect();

        let claim_set = ClaimVerifier::verify(&claims, source_text, source_cid);
        let k = self.kernel.lock().unwrap();
        let config = match profile {
            "medical" => JudgmentConfig::medical(),
            "financial" => JudgmentConfig::financial(),
            _ => JudgmentConfig::default(),
        };
        let j = JudgmentEngine::judge(&k, Some(&claim_set), &config);

        Python::with_gil(|py| {
            let mut result = judgment_to_dict(&j, py);
            // Also include claim verification results
            result.insert("confirmed_count".into(), claim_set.confirmed_count().into_py(py));
            result.insert("rejected_count".into(), claim_set.rejected_count().into_py(py));
            result.insert("validity_ratio".into(), claim_set.validity_ratio().into_py(py));
            result
        })
    }

    // ── Perception Engine ─────────────────────────────────────────

    /// Observe raw input: write to kernel, extract entities, verify claims, score quality.
    /// Returns dict with: cid, entities, quality_score, quality_grade, warnings, timestamp.
    #[pyo3(signature = (agent_pid, content, user, pipeline, session_id=None, extract_claims=false))]
    fn perceive_observe(
        &self, agent_pid: &str, content: &str, user: &str, pipeline: &str,
        session_id: Option<&str>, extract_claims: bool,
    ) -> PyResult<std::collections::HashMap<String, PyObject>> {
        let mut k = self.kernel.lock().unwrap();
        let grounding = self.grounding.lock().unwrap();
        let mut config = ObservationConfig::default();
        if extract_claims { config = config.with_claims(); }
        let obs = PerceptionEngine::observe(
            &mut k, agent_pid, content, user, pipeline,
            session_id, None, grounding.as_ref(), &config,
        ).map_err(PyRuntimeError::new_err)?;
        Ok(Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("cid".into(), obs.cid.into_py(py));
            m.insert("entities".into(), obs.entities.into_py(py));
            m.insert("quality_score".into(), obs.quality_score.into_py(py));
            m.insert("quality_grade".into(), obs.quality_grade.into_py(py));
            m.insert("warnings".into(), obs.warnings.into_py(py));
            m.insert("timestamp".into(), obs.timestamp.into_py(py));
            m
        }))
    }

    /// Perceive current context: retrieve relevant memories + judge kernel state.
    /// Returns dict with: memories (list), total_found, judgment (dict), namespace.
    #[pyo3(signature = (namespace, session_id=None, limit=20))]
    fn perceive_context(
        &self, namespace: &str, session_id: Option<&str>, limit: usize,
    ) -> std::collections::HashMap<String, PyObject> {
        let k = self.kernel.lock().unwrap();
        let ctx = PerceptionEngine::perceive(&k, namespace, session_id, limit, &JudgmentConfig::default());
        Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            let mems: Vec<std::collections::HashMap<String, PyObject>> = ctx.memories.iter().map(|s| summary_to_dict(s, py)).collect();
            m.insert("memories".into(), mems.into_py(py));
            m.insert("total_found".into(), ctx.total_found.into_py(py));
            m.insert("judgment".into(), judgment_to_dict(&ctx.judgment, py).into_py(py));
            m.insert("namespace".into(), ctx.namespace.into_py(py));
            m.insert("active_session".into(), ctx.active_session.into_py(py));
            m
        })
    }

    // ── Knowledge Engine ─────────────────────────────────────────

    /// Ingest namespace into the binding engine's knowledge graph.
    /// Returns dict with: entities_upserted, total_entities, contradiction_detected, interference_score.
    fn knowledge_ingest_full(&self, agent_pid: &str, namespace: &str) -> std::collections::HashMap<String, PyObject> {
        let k = self.kernel.lock().unwrap();
        let mut binding = self.binding.lock().unwrap();
        let result = binding.knowledge.ingest(&k, namespace, agent_pid);
        Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("entities_upserted".into(), result.entities_upserted.into_py(py));
            m.insert("total_entities".into(), result.total_entities.into_py(py));
            m.insert("contradiction_detected".into(), result.contradiction_detected.into_py(py));
            m.insert("interference_score".into(), result.interference_score.into_py(py));
            m.insert("warnings".into(), result.warnings.into_py(py));
            m
        })
    }

    /// Retrieve knowledge using RAG pipeline.
    #[pyo3(signature = (entities=None, keywords=None, token_budget=4096, max_facts=20))]
    fn knowledge_retrieve(
        &self, entities: Option<Vec<String>>, keywords: Option<Vec<String>>,
        token_budget: usize, max_facts: usize,
    ) -> std::collections::HashMap<String, PyObject> {
        let k = self.kernel.lock().unwrap();
        let binding = self.binding.lock().unwrap();
        let grounding = self.grounding.lock().unwrap();
        let ent = entities.unwrap_or_default();
        let kw = keywords.unwrap_or_default();
        let ctx = binding.knowledge.retrieve(&k, &ent, &kw, token_budget, max_facts, grounding.as_ref());
        let prompt_ctx = ctx.to_prompt_context();
        Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("facts_included".into(), ctx.facts_included.into_py(py));
            m.insert("tokens_used".into(), ctx.tokens_used.into_py(py));
            m.insert("prompt_context".into(), prompt_ctx.into_py(py));
            m.insert("source_cids".into(), ctx.source_cids.into_py(py));
            m.insert("entities".into(), ctx.entities.into_py(py));
            m
        })
    }

    /// Compile knowledge — cache expensive reasoning for reuse.
    #[pyo3(signature = (agent_pid, insight, source_cids, entities, confidence=0.9, reasoning_steps=1))]
    fn knowledge_compile(
        &self, agent_pid: &str, insight: &str, source_cids: Vec<String>,
        entities: Vec<String>, confidence: f64, reasoning_steps: usize,
    ) -> PyResult<std::collections::HashMap<String, PyObject>> {
        let mut k = self.kernel.lock().unwrap();
        let mut binding = self.binding.lock().unwrap();
        let compiled = binding.knowledge.compile(
            &mut k, agent_pid, insight, source_cids, entities, confidence, reasoning_steps,
        ).map_err(PyRuntimeError::new_err)?;
        Ok(Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("cid".into(), compiled.cid.into_py(py));
            m.insert("insight".into(), compiled.insight.into_py(py));
            m.insert("confidence".into(), compiled.confidence.into_py(py));
            m.insert("reasoning_steps".into(), compiled.reasoning_steps.into_py(py));
            m
        }))
    }

    /// Check for contradictions in the knowledge graph.
    fn knowledge_contradictions(&self, agent_pid: &str, namespace: &str) -> std::collections::HashMap<String, PyObject> {
        let k = self.kernel.lock().unwrap();
        let binding = self.binding.lock().unwrap();
        let report = binding.knowledge.check_contradictions(&k, namespace, agent_pid);
        Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("has_contradictions".into(), report.has_contradictions.into_py(py));
            m.insert("interference_score".into(), report.interference_score.into_py(py));
            m.insert("phase_delta".into(), report.phase_delta.into_py(py));
            m.insert("warnings".into(), report.warnings.into_py(py));
            m
        })
    }

    // ── Logic Engine ─────────────────────────────────────────────

    /// Create a plan with steps. Returns dict with: goal, plan_cid, steps (count), progress.
    fn logic_plan(
        &self, agent_pid: &str, goal: &str, steps: Vec<String>,
    ) -> PyResult<std::collections::HashMap<String, PyObject>> {
        let mut k = self.kernel.lock().unwrap();
        let step_refs: Vec<&str> = steps.iter().map(|s| s.as_str()).collect();
        let plan = LogicEngine::plan(&mut k, agent_pid, goal, &step_refs, &[])
            .map_err(PyRuntimeError::new_err)?;
        Ok(Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            let progress = plan.progress();
            let step_count = plan.steps.len();
            m.insert("goal".into(), plan.goal.into_py(py));
            m.insert("plan_cid".into(), plan.plan_cid.into_py(py));
            m.insert("step_count".into(), step_count.into_py(py));
            m.insert("progress".into(), progress.into_py(py));
            m
        }))
    }

    /// Record a reasoning step. Returns the CID of the step.
    #[pyo3(signature = (agent_pid, query, thought, action=None, result=None, evidence_cids=None))]
    fn logic_reason(
        &self, agent_pid: &str, query: &str, thought: &str,
        action: Option<&str>, result: Option<&str>, evidence_cids: Option<Vec<String>>,
    ) -> PyResult<String> {
        let mut k = self.kernel.lock().unwrap();
        let mut chain = ReasoningChain::new(query);
        LogicEngine::record_reasoning_step(
            &mut k, agent_pid, &mut chain, thought, action, result,
            evidence_cids.unwrap_or_default(),
        ).map_err(PyRuntimeError::new_err)?;
        Ok(chain.steps.last().and_then(|s| s.cid.clone()).unwrap_or_default())
    }

    /// Reflect on reasoning quality. Returns dict with: quality_score, grade, weaknesses, suggestions.
    fn logic_reflect(&self, agent_pid: &str) -> std::collections::HashMap<String, PyObject> {
        let k = self.kernel.lock().unwrap();
        let chain = ReasoningChain::new("reflection");
        let r = LogicEngine::reflect(&k, &chain, &JudgmentConfig::default());
        Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("quality_score".into(), r.quality_score.into_py(py));
            m.insert("grade".into(), r.grade.into_py(py));
            m.insert("evidence_coverage".into(), r.evidence_coverage.into_py(py));
            m.insert("coherence".into(), r.coherence.into_py(py));
            m.insert("completeness".into(), r.completeness.into_py(py));
            m.insert("weaknesses".into(), r.weaknesses.into_py(py));
            m.insert("suggestions".into(), r.suggestions.into_py(py));
            m.insert("should_reconsider".into(), r.should_reconsider.into_py(py));
            m
        })
    }

    // ── Binding Engine (Cognitive Loop) ──────────────────────────

    /// Run one full cognitive cycle: perceive → retrieve → reason → reflect → act.
    /// Returns dict with: cycle_number, observation_cid, facts_retrieved, reasoning_steps,
    /// quality_score, contradiction_detected, decision_cid, warnings.
    #[pyo3(signature = (agent_pid, input, user, pipeline, session_id=None, goal="process input", steps=None))]
    fn cognitive_cycle(
        &self, agent_pid: &str, input: &str, user: &str, pipeline: &str,
        session_id: Option<&str>, goal: &str, steps: Option<Vec<String>>,
    ) -> PyResult<std::collections::HashMap<String, PyObject>> {
        let mut k = self.kernel.lock().unwrap();
        let mut binding = self.binding.lock().unwrap();
        let step_strs = steps.unwrap_or_default();
        let step_refs: Vec<&str> = step_strs.iter().map(|s| s.as_str()).collect();
        let summary = binding.cognitive_cycle(
            &mut k, agent_pid, input, user, pipeline, session_id, None, goal, &step_refs,
        ).map_err(PyRuntimeError::new_err)?;
        Ok(Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("cycle_number".into(), summary.cycle_number.into_py(py));
            m.insert("observation_cid".into(), summary.observation_cid.into_py(py));
            m.insert("facts_retrieved".into(), summary.facts_retrieved.into_py(py));
            m.insert("reasoning_steps".into(), summary.reasoning_steps.into_py(py));
            m.insert("quality_score".into(), summary.quality_score.into_py(py));
            m.insert("contradiction_detected".into(), summary.contradiction_detected.into_py(py));
            m.insert("decision_cid".into(), summary.decision_cid.into_py(py));
            m.insert("warnings".into(), summary.warnings.into_py(py));
            m
        }))
    }

    /// Get cognitive report for the binding engine.
    fn cognitive_report(&self, agent_pid: &str, namespace: &str) -> std::collections::HashMap<String, PyObject> {
        let binding = self.binding.lock().unwrap();
        let report = binding.report(agent_pid, namespace);
        Python::with_gil(|py| {
            let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
            m.insert("agent_pid".into(), report.agent_pid.into_py(py));
            m.insert("namespace".into(), report.namespace.into_py(py));
            m.insert("total_cycles".into(), report.total_cycles.into_py(py));
            m.insert("total_observations".into(), report.total_observations.into_py(py));
            m.insert("total_reasoning_steps".into(), report.total_reasoning_steps.into_py(py));
            m.insert("total_decisions".into(), report.total_decisions.into_py(py));
            m.insert("contradictions_detected".into(), report.contradictions_detected.into_py(py));
            m.insert("compilations".into(), report.compilations.into_py(py));
            m.insert("final_quality_score".into(), report.final_quality_score.into_py(py));
            m
        })
    }

    /// Get the binding engine's cognitive phase.
    fn cognitive_phase(&self) -> String {
        let binding = self.binding.lock().unwrap();
        binding.phase().to_string()
    }

    /// Get the binding engine's cycle count.
    fn cognitive_cycle_count(&self) -> u32 {
        let binding = self.binding.lock().unwrap();
        binding.cycle_count()
    }

    // ═══════════════════════════════════════════════════════════
    // AAPI — Action Authorization Engine
    // ═══════════════════════════════════════════════════════════

    /// Add a policy with rules. Each rule is a dict with keys:
    /// effect ("allow"/"deny"/"require_approval"), action_pattern, resource_pattern (optional),
    /// roles (list, optional), priority (int).
    #[pyo3(signature = (id, name, rules))]
    fn add_policy(&self, id: &str, name: &str, rules: Vec<std::collections::HashMap<String, PyObject>>, py: Python<'_>) -> PyResult<()> {
        let mut parsed: Vec<PolicyRule> = Vec::new();
        for r in &rules {
            let eff_str: String = r.get("effect").map(|v| v.extract::<String>(py).unwrap_or_default()).unwrap_or_default();
            let effect = match eff_str.as_str() {
                "deny" => PolicyEffect::Deny,
                "require_approval" => PolicyEffect::RequireApproval,
                _ => PolicyEffect::Allow,
            };
            let action_pattern: String = r.get("action_pattern").map(|v| v.extract::<String>(py).unwrap_or_default()).unwrap_or_default();
            let resource_pattern: Option<String> = r.get("resource_pattern").and_then(|v| v.extract::<String>(py).ok());
            let roles: Vec<String> = r.get("roles").and_then(|v| v.extract::<Vec<String>>(py).ok()).unwrap_or_default();
            let priority: i32 = r.get("priority").and_then(|v| v.extract::<i32>(py).ok()).unwrap_or(0);
            parsed.push(PolicyRule { effect, action_pattern, resource_pattern, roles, priority });
        }
        let mut eng = self.aapi.lock().unwrap();
        eng.add_policy(id, name, parsed);
        Ok(())
    }

    fn remove_policy(&self, id: &str) {
        self.aapi.lock().unwrap().remove_policy(id);
    }

    fn policy_count(&self) -> usize {
        self.aapi.lock().unwrap().policy_count()
    }

    fn add_hipaa_policy(&self) {
        self.aapi.lock().unwrap().add_hipaa_policy();
    }

    fn add_financial_policy(&self) {
        self.aapi.lock().unwrap().add_financial_policy();
    }

    /// Evaluate policy for an action. Returns dict with allowed, effect, reason, matched_rule, requires_approval.
    #[pyo3(signature = (action, resource, role=None))]
    fn evaluate_policy(&self, action: &str, resource: &str, role: Option<&str>, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let eng = self.aapi.lock().unwrap();
        let d = eng.evaluate_policy(action, resource, role);
        let mut m = std::collections::HashMap::new();
        m.insert("allowed".into(), d.allowed.into_py(py));
        m.insert("effect".into(), d.effect.into_py(py));
        m.insert("reason".into(), d.reason.into_py(py));
        m.insert("matched_rule".into(), d.matched_rule.into_py(py));
        m.insert("requires_approval".into(), d.requires_approval.into_py(py));
        m
    }

    /// Authorize a tool call — checks budgets + capabilities + policies.
    #[pyo3(signature = (agent_pid, action, resource, role=None))]
    fn authorize_tool(&self, agent_pid: &str, action: &str, resource: &str, role: Option<&str>, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let eng = self.aapi.lock().unwrap();
        let d = eng.authorize_tool(agent_pid, action, resource, role);
        let mut m = std::collections::HashMap::new();
        m.insert("allowed".into(), d.allowed.into_py(py));
        m.insert("effect".into(), d.effect.into_py(py));
        m.insert("reason".into(), d.reason.into_py(py));
        m.insert("matched_rule".into(), d.matched_rule.into_py(py));
        m.insert("requires_approval".into(), d.requires_approval.into_py(py));
        m
    }

    // ── Budget Management ──

    fn create_budget(&self, agent_pid: &str, resource: &str, limit: f64) {
        self.aapi.lock().unwrap().create_budget(agent_pid, resource, limit);
    }

    fn consume_budget(&self, agent_pid: &str, resource: &str, amount: f64) -> bool {
        self.aapi.lock().unwrap().consume_budget(agent_pid, resource, amount)
    }

    fn check_budget(&self, agent_pid: &str, resource: &str) -> f64 {
        self.aapi.lock().unwrap().check_budget(agent_pid, resource)
    }

    // ── Capability Delegation (UCAN-style) ──

    #[pyo3(signature = (issuer, subject, actions, resources, ttl_hours=24))]
    fn issue_capability(&self, issuer: &str, subject: &str, actions: Vec<String>, resources: Vec<String>, ttl_hours: u64, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let mut eng = self.aapi.lock().unwrap();
        let cap = eng.issue_capability(issuer, subject, actions.clone(), resources.clone(), ttl_hours);
        let mut m = std::collections::HashMap::new();
        m.insert("token_id".into(), cap.token_id.into_py(py));
        m.insert("issuer".into(), cap.issuer.into_py(py));
        m.insert("subject".into(), cap.subject.into_py(py));
        m.insert("actions".into(), actions.into_py(py));
        m.insert("resources".into(), resources.into_py(py));
        m.insert("expires_at".into(), cap.expires_at.into_py(py));
        m
    }

    #[pyo3(signature = (parent_token_id, new_subject, remove_actions=vec![]))]
    fn delegate_capability(&self, parent_token_id: &str, new_subject: &str, remove_actions: Vec<String>, py: Python<'_>) -> PyResult<std::collections::HashMap<String, PyObject>> {
        let refs: Vec<&str> = remove_actions.iter().map(|s| s.as_str()).collect();
        let mut eng = self.aapi.lock().unwrap();
        let cap = eng.delegate_capability(parent_token_id, new_subject, &refs)
            .ok_or_else(|| PyRuntimeError::new_err("Parent capability not found or invalid"))?;
        let mut m = std::collections::HashMap::new();
        m.insert("token_id".into(), cap.token_id.into_py(py));
        m.insert("issuer".into(), cap.issuer.into_py(py));
        m.insert("subject".into(), cap.subject.into_py(py));
        m.insert("actions".into(), cap.actions.into_py(py));
        m.insert("resources".into(), cap.resources.into_py(py));
        m.insert("parent_token_id".into(), cap.parent_token_id.into_py(py));
        m.insert("expires_at".into(), cap.expires_at.into_py(py));
        Ok(m)
    }

    fn revoke_capability(&self, token_id: &str) {
        self.aapi.lock().unwrap().revoke_capability(token_id);
    }

    fn verify_capability(&self, token_id: &str) -> Option<bool> {
        self.aapi.lock().unwrap().verify_capability(token_id)
    }

    fn capability_count(&self) -> usize {
        self.aapi.lock().unwrap().capability_count()
    }

    // ── Action Records (audit trail) ──

    #[pyo3(signature = (intent, action, target, agent_pid, outcome, evidence=vec![], confidence=None, regulations=vec![]))]
    fn record_action(&self, intent: &str, action: &str, target: &str, agent_pid: &str, outcome: &str, evidence: Vec<String>, confidence: Option<f64>, regulations: Vec<String>, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let mut eng = self.aapi.lock().unwrap();
        let e = eng.record_action(intent, action, target, agent_pid, outcome, evidence, confidence, regulations);
        let mut m = std::collections::HashMap::new();
        m.insert("record_id".into(), e.record_id.into_py(py));
        m.insert("action".into(), e.action.into_py(py));
        m.insert("outcome".into(), e.outcome.into_py(py));
        m.insert("timestamp".into(), e.timestamp.into_py(py));
        m
    }

    #[pyo3(signature = (agent_pid=None))]
    fn list_actions(&self, agent_pid: Option<&str>, py: Python<'_>) -> Vec<std::collections::HashMap<String, PyObject>> {
        let eng = self.aapi.lock().unwrap();
        eng.list_actions(agent_pid).iter().map(|e| {
            let mut m = std::collections::HashMap::new();
            m.insert("record_id".into(), e.record_id.clone().into_py(py));
            m.insert("intent".into(), e.intent.clone().into_py(py));
            m.insert("action".into(), e.action.clone().into_py(py));
            m.insert("target".into(), e.target.clone().into_py(py));
            m.insert("agent_pid".into(), e.agent_pid.clone().into_py(py));
            m.insert("outcome".into(), e.outcome.clone().into_py(py));
            m.insert("confidence".into(), e.confidence.into_py(py));
            m.insert("regulations".into(), e.regulations.clone().into_py(py));
            m.insert("timestamp".into(), e.timestamp.into_py(py));
            m
        }).collect()
    }

    fn action_count(&self) -> usize {
        self.aapi.lock().unwrap().action_count()
    }

    // ── Interaction Logging ──

    #[pyo3(signature = (agent_pid, itype, target, operation, status, duration_ms, tokens=None, cost_usd=None))]
    fn log_interaction(&self, agent_pid: &str, itype: &str, target: &str, operation: &str, status: &str, duration_ms: u64, tokens: Option<u64>, cost_usd: Option<f64>, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let mut eng = self.aapi.lock().unwrap();
        let e = eng.log_interaction(agent_pid, itype, target, operation, status, duration_ms, tokens, cost_usd);
        let mut m = std::collections::HashMap::new();
        m.insert("id".into(), e.id.into_py(py));
        m.insert("itype".into(), e.itype.into_py(py));
        m.insert("target".into(), e.target.into_py(py));
        m.insert("timestamp".into(), e.timestamp.into_py(py));
        m
    }

    #[pyo3(signature = (agent_pid=None))]
    fn list_interactions(&self, agent_pid: Option<&str>, py: Python<'_>) -> Vec<std::collections::HashMap<String, PyObject>> {
        let eng = self.aapi.lock().unwrap();
        eng.list_interactions(agent_pid).iter().map(|e| {
            let mut m = std::collections::HashMap::new();
            m.insert("id".into(), e.id.clone().into_py(py));
            m.insert("agent_pid".into(), e.agent_pid.clone().into_py(py));
            m.insert("itype".into(), e.itype.clone().into_py(py));
            m.insert("target".into(), e.target.clone().into_py(py));
            m.insert("operation".into(), e.operation.clone().into_py(py));
            m.insert("status".into(), e.status.clone().into_py(py));
            m.insert("duration_ms".into(), e.duration_ms.into_py(py));
            m.insert("tokens".into(), e.tokens.into_py(py));
            m.insert("cost_usd".into(), e.cost_usd.into_py(py));
            m.insert("timestamp".into(), e.timestamp.into_py(py));
            m
        }).collect()
    }

    fn interaction_count(&self) -> usize {
        self.aapi.lock().unwrap().interaction_count()
    }

    // ── Compliance ──

    #[pyo3(signature = (regulations, data_classification=None, retention_days=365, requires_human_review=false))]
    fn set_compliance(&self, regulations: Vec<String>, data_classification: Option<String>, retention_days: u64, requires_human_review: bool) {
        self.aapi.lock().unwrap().set_compliance(ComplianceConfig {
            regulations, data_classification, retention_days, requires_human_review,
        });
    }

    // ═══════════════════════════════════════════════════════════
    // Kernel Ops — Scalability, Data Management, Diagnostics
    // ═══════════════════════════════════════════════════════════

    /// Kernel statistics: packets, agents, sessions, audit entries, namespaces.
    fn kernel_stats(&self, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let ops = KernelOps::new(self.kernel.clone());
        let s = ops.stats();
        let mut m = std::collections::HashMap::new();
        m.insert("total_packets".into(), s.total_packets.into_py(py));
        m.insert("total_agents".into(), s.total_agents.into_py(py));
        m.insert("total_sessions".into(), s.total_sessions.into_py(py));
        m.insert("total_audit_entries".into(), s.total_audit_entries.into_py(py));
        m.insert("active_agents".into(), s.active_agents.into_py(py));
        m.insert("active_sessions".into(), s.active_sessions.into_py(py));
        m.insert("namespaces".into(), s.namespaces.into_py(py));
        m
    }

    /// List all namespaces with packet counts and owning agents.
    fn list_namespaces(&self, py: Python<'_>) -> Vec<std::collections::HashMap<String, PyObject>> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.list_namespaces().iter().map(|n| {
            let mut m = std::collections::HashMap::new();
            m.insert("name".into(), n.name.clone().into_py(py));
            m.insert("packet_count".into(), n.packet_count.into_py(py));
            m.insert("agents".into(), n.agents.clone().into_py(py));
            m
        }).collect()
    }

    /// Get info about a specific namespace.
    fn namespace_info(&self, namespace: &str, py: Python<'_>) -> Option<std::collections::HashMap<String, PyObject>> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.namespace_info(namespace).map(|n| {
            let mut m = std::collections::HashMap::new();
            m.insert("name".into(), n.name.into_py(py));
            m.insert("packet_count".into(), n.packet_count.into_py(py));
            m.insert("agents".into(), n.agents.into_py(py));
            m
        })
    }

    /// List all sessions with metadata.
    fn list_sessions(&self, py: Python<'_>) -> Vec<std::collections::HashMap<String, PyObject>> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.list_sessions().iter().map(|s| {
            let mut m = std::collections::HashMap::new();
            m.insert("session_id".into(), s.session_id.clone().into_py(py));
            m.insert("agent_id".into(), s.agent_id.clone().into_py(py));
            m.insert("namespace".into(), s.namespace.clone().into_py(py));
            m.insert("label".into(), s.label.clone().into_py(py));
            m.insert("packet_count".into(), s.packet_count.into_py(py));
            m.insert("total_tokens".into(), s.total_tokens.into_py(py));
            m.insert("started_at".into(), s.started_at.into_py(py));
            m.insert("ended_at".into(), s.ended_at.into_py(py));
            m.insert("is_active".into(), s.is_active.into_py(py));
            m.insert("tier".into(), s.tier.clone().into_py(py));
            m
        }).collect()
    }

    /// List all registered agents with full metadata.
    fn list_agents(&self, py: Python<'_>) -> Vec<std::collections::HashMap<String, PyObject>> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.list_agents().iter().map(|a| {
            let mut m = std::collections::HashMap::new();
            m.insert("pid".into(), a.pid.clone().into_py(py));
            m.insert("name".into(), a.name.clone().into_py(py));
            m.insert("status".into(), a.status.clone().into_py(py));
            m.insert("namespace".into(), a.namespace.clone().into_py(py));
            m.insert("total_packets".into(), a.total_packets.into_py(py));
            m.insert("total_tokens".into(), a.total_tokens.into_py(py));
            m.insert("total_cost_usd".into(), a.total_cost_usd.into_py(py));
            m.insert("memory_used_packets".into(), a.memory_used_packets.into_py(py));
            m.insert("memory_quota_packets".into(), a.memory_quota_packets.into_py(py));
            m.insert("active_sessions".into(), a.active_sessions.into_py(py));
            m.insert("model".into(), a.model.clone().into_py(py));
            m.insert("role".into(), a.role.clone().into_py(py));
            m.insert("phase".into(), a.phase.clone().into_py(py));
            m
        }).collect()
    }

    /// Get detailed info about a specific agent.
    fn agent_detail(&self, pid: &str, py: Python<'_>) -> Option<std::collections::HashMap<String, PyObject>> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.agent_info(pid).map(|a| {
            let mut m = std::collections::HashMap::new();
            m.insert("pid".into(), a.pid.into_py(py));
            m.insert("name".into(), a.name.into_py(py));
            m.insert("status".into(), a.status.into_py(py));
            m.insert("namespace".into(), a.namespace.into_py(py));
            m.insert("total_packets".into(), a.total_packets.into_py(py));
            m.insert("total_tokens".into(), a.total_tokens.into_py(py));
            m.insert("total_cost_usd".into(), a.total_cost_usd.into_py(py));
            m.insert("memory_used_packets".into(), a.memory_used_packets.into_py(py));
            m.insert("memory_quota_packets".into(), a.memory_quota_packets.into_py(py));
            m.insert("active_sessions".into(), a.active_sessions.into_py(py));
            m.insert("registered_at".into(), a.registered_at.into_py(py));
            m.insert("last_active_at".into(), a.last_active_at.into_py(py));
            m.insert("model".into(), a.model.into_py(py));
            m.insert("role".into(), a.role.into_py(py));
            m.insert("phase".into(), a.phase.into_py(py));
            m
        })
    }

    /// Suspend an agent by PID.
    fn suspend_agent(&self, agent_pid: &str) -> PyResult<()> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.suspend_agent(agent_pid, agent_pid).map_err(PyRuntimeError::new_err)
    }

    /// Resume a suspended agent.
    fn resume_agent(&self, agent_pid: &str) -> PyResult<()> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.resume_agent(agent_pid).map_err(PyRuntimeError::new_err)
    }

    /// Terminate an agent.
    #[pyo3(signature = (agent_pid, reason="terminated by user"))]
    fn terminate_agent(&self, agent_pid: &str, reason: &str) -> PyResult<()> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.terminate_agent(agent_pid, agent_pid, reason).map_err(PyRuntimeError::new_err)
    }

    /// Get the last N audit log entries.
    #[pyo3(signature = (limit=50))]
    fn audit_tail(&self, limit: usize, py: Python<'_>) -> Vec<std::collections::HashMap<String, PyObject>> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.audit_tail(limit).iter().map(|e| {
            let mut m = std::collections::HashMap::new();
            m.insert("audit_id".into(), e.audit_id.clone().into_py(py));
            m.insert("timestamp".into(), e.timestamp.into_py(py));
            m.insert("operation".into(), e.operation.clone().into_py(py));
            m.insert("agent_pid".into(), e.agent_pid.clone().into_py(py));
            m.insert("target".into(), e.target.clone().into_py(py));
            m.insert("outcome".into(), e.outcome.clone().into_py(py));
            m.insert("reason".into(), e.reason.clone().into_py(py));
            m.insert("error".into(), e.error.clone().into_py(py));
            m.insert("duration_us".into(), e.duration_us.into_py(py));
            m
        }).collect()
    }

    /// Get audit entries for a specific agent.
    #[pyo3(signature = (agent_pid, limit=50))]
    fn audit_by_agent(&self, agent_pid: &str, limit: usize, py: Python<'_>) -> Vec<std::collections::HashMap<String, PyObject>> {
        let ops = KernelOps::new(self.kernel.clone());
        ops.audit_by_agent(agent_pid, limit).iter().map(|e| {
            let mut m = std::collections::HashMap::new();
            m.insert("audit_id".into(), e.audit_id.clone().into_py(py));
            m.insert("timestamp".into(), e.timestamp.into_py(py));
            m.insert("operation".into(), e.operation.clone().into_py(py));
            m.insert("agent_pid".into(), e.agent_pid.clone().into_py(py));
            m.insert("target".into(), e.target.clone().into_py(py));
            m.insert("outcome".into(), e.outcome.clone().into_py(py));
            m
        }).collect()
    }

    /// Kernel health report: memory pressure, warnings, diagnostics.
    fn kernel_health(&self, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let ops = KernelOps::new(self.kernel.clone());
        let h = ops.health();
        let mut m = std::collections::HashMap::new();
        m.insert("healthy".into(), h.healthy.into_py(py));
        m.insert("total_packets".into(), h.total_packets.into_py(py));
        m.insert("total_agents".into(), h.total_agents.into_py(py));
        m.insert("total_audit_entries".into(), h.total_audit_entries.into_py(py));
        m.insert("memory_pressure".into(), h.memory_pressure.into_py(py));
        m.insert("warnings".into(), h.warnings.into_py(py));
        m
    }

    /// Export full kernel state as JSON string.
    #[pyo3(signature = (audit_tail_limit=100))]
    fn kernel_export(&self, audit_tail_limit: usize) -> String {
        let ops = KernelOps::new(self.kernel.clone());
        ops.export_json(audit_tail_limit)
    }

    // ═══════════════════════════════════════════════════════════
    // Custom Folders — Dynamic Namespaced Storage (like mkdir)
    // ═══════════════════════════════════════════════════════════

    /// Create a storage folder for an agent. Like `mkdir /agent:{pid}/{name}`.
    fn create_agent_folder(&self, agent_pid: &str, folder_name: &str, description: &str) -> PyResult<()> {
        let namespace = format!("agent:{}/{}", agent_pid, folder_name);
        let owner = connector_engine::engine_store::FolderOwner::Agent(agent_pid.to_string());
        let mut es = self.engine_store.lock().unwrap();
        es.create_folder(&namespace, &owner, description)
            .map_err(|e| PyRuntimeError::new_err(e.message))
    }

    /// Create a storage folder for a tool. Like `mkdir /tool:{name}/{folder}`.
    fn create_tool_folder(&self, tool_name: &str, folder_name: &str, description: &str) -> PyResult<()> {
        let namespace = format!("tool:{}/{}", tool_name, folder_name);
        let owner = connector_engine::engine_store::FolderOwner::Tool(tool_name.to_string());
        let mut es = self.engine_store.lock().unwrap();
        es.create_folder(&namespace, &owner, description)
            .map_err(|e| PyRuntimeError::new_err(e.message))
    }

    /// Write a key-value pair to a folder. Auto-creates folder if needed.
    fn folder_put(&self, namespace: &str, key: &str, value: &str) -> PyResult<()> {
        let v: serde_json::Value = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));
        let mut es = self.engine_store.lock().unwrap();
        es.folder_put(namespace, key, &v)
            .map_err(|e| PyRuntimeError::new_err(e.message))
    }

    /// Read a value from a folder by key. Returns JSON string or None.
    fn folder_get(&self, namespace: &str, key: &str) -> PyResult<Option<String>> {
        let es = self.engine_store.lock().unwrap();
        es.folder_get(namespace, key)
            .map(|opt| opt.map(|v| serde_json::to_string(&v).unwrap_or_default()))
            .map_err(|e| PyRuntimeError::new_err(e.message))
    }

    /// Delete a key from a folder.
    fn folder_delete(&self, namespace: &str, key: &str) -> PyResult<()> {
        let mut es = self.engine_store.lock().unwrap();
        es.folder_delete(namespace, key)
            .map_err(|e| PyRuntimeError::new_err(e.message))
    }

    /// List all keys in a folder. Optional prefix filter.
    #[pyo3(signature = (namespace, prefix=None))]
    fn folder_keys(&self, namespace: &str, prefix: Option<&str>) -> PyResult<Vec<String>> {
        let es = self.engine_store.lock().unwrap();
        es.folder_keys(namespace, prefix)
            .map_err(|e| PyRuntimeError::new_err(e.message))
    }

    /// Delete an entire folder and all its data.
    fn delete_folder(&self, namespace: &str) -> PyResult<()> {
        let mut es = self.engine_store.lock().unwrap();
        es.delete_folder(namespace)
            .map_err(|e| PyRuntimeError::new_err(e.message))
    }

    /// List all folders. Returns list of dicts with namespace, owner, description, entry_count.
    fn list_folders(&self, py: Python<'_>) -> PyResult<Vec<std::collections::HashMap<String, PyObject>>> {
        let es = self.engine_store.lock().unwrap();
        let folders = es.list_folders(None)
            .map_err(|e| PyRuntimeError::new_err(e.message))?;
        Ok(folders.iter().map(|f| {
            let mut m = std::collections::HashMap::new();
            m.insert("namespace".into(), f.namespace.clone().into_py(py));
            m.insert("owner".into(), format!("{:?}", f.owner).into_py(py));
            m.insert("description".into(), f.description.clone().into_py(py));
            m.insert("entry_count".into(), f.entry_count.into_py(py));
            m.insert("created_at".into(), f.created_at.into_py(py));
            m
        }).collect())
    }

    /// Engine store statistics: folder count, tool count, policy count.
    fn engine_stats(&self, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
        let es = self.engine_store.lock().unwrap();
        let folder_count = es.list_folders(None).map(|f| f.len()).unwrap_or(0);
        let tool_count = es.load_tool_defs().map(|t| t.len()).unwrap_or(0);
        let policy_count = es.load_policies().map(|p| p.len()).unwrap_or(0);
        let mut m = std::collections::HashMap::new();
        m.insert("folders".into(), folder_count.into_py(py));
        m.insert("tools".into(), tool_count.into_py(py));
        m.insert("policies".into(), policy_count.into_py(py));
        m
    }

    /// Print the storage zone layout as a tree string.
    fn storage_tree(&self) -> String {
        self.storage_layout.to_tree()
    }

    fn __repr__(&self) -> String {
        let llm = self.inner.llm_config()
            .map(|c| format!("{}:{}", c.provider, c.model))
            .unwrap_or_else(|| "none".into());
        let k = self.kernel.lock().unwrap();
        let knot = self.knot.lock().unwrap();
        let binding = self.binding.lock().unwrap();
        let aapi = self.aapi.lock().unwrap();
        let es = self.engine_store.lock().unwrap();
        let folders = es.list_folders(None).map(|f| f.len()).unwrap_or(0);
        format!("Connector(llm='{}', packets={}, agents={}, audit={}, entities={}, cycles={}, policies={}, capabilities={}, folders={})",
            llm, k.packet_count(), k.agents().len(), k.audit_log().len(), knot.node_count(),
            binding.cycle_count(), aapi.policy_count(), aapi.capability_count(), folders)
    }
}

// ── FFI Helpers ─────────────────────────────────────────────────

fn summary_to_dict(s: &PacketSummary, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
    let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
    m.insert("cid".into(), s.cid.clone().into_py(py));
    m.insert("text".into(), s.text.clone().into_py(py));
    m.insert("packet_type".into(), s.packet_type.clone().into_py(py));
    m.insert("timestamp".into(), s.timestamp.into_py(py));
    m.insert("entities".into(), s.entities.clone().into_py(py));
    m.insert("tags".into(), s.tags.clone().into_py(py));
    m.insert("namespace".into(), s.namespace.clone().into_py(py));
    m.insert("session_id".into(), s.session_id.clone().into_py(py));
    m.insert("tier".into(), s.tier.clone().into_py(py));
    m
}

fn judgment_to_dict(j: &connector_engine::judgment::JudgmentResult, py: Python<'_>) -> std::collections::HashMap<String, PyObject> {
    let mut m: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
    m.insert("score".into(), j.score.into_py(py));
    m.insert("grade".into(), j.grade.clone().into_py(py));
    m.insert("explanation".into(), j.explanation.clone().into_py(py));
    m.insert("operations_analyzed".into(), j.operations_analyzed.into_py(py));
    m.insert("warnings".into(), j.warnings.clone().into_py(py));
    // 8 dimensions
    let mut dims: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
    dims.insert("cid_integrity".into(), j.dimensions.cid_integrity.into_py(py));
    dims.insert("audit_coverage".into(), j.dimensions.audit_coverage.into_py(py));
    dims.insert("access_control".into(), j.dimensions.access_control.into_py(py));
    dims.insert("evidence_quality".into(), j.dimensions.evidence_quality.into_py(py));
    dims.insert("claim_coverage".into(), j.dimensions.claim_coverage.into_py(py));
    dims.insert("temporal_freshness".into(), j.dimensions.temporal_freshness.into_py(py));
    dims.insert("contradiction_score".into(), j.dimensions.contradiction_score.into_py(py));
    dims.insert("source_credibility".into(), j.dimensions.source_credibility.into_py(py));
    m.insert("dimensions".into(), dims.into_py(py));
    // Weighted scores
    let mut ws: std::collections::HashMap<String, PyObject> = std::collections::HashMap::new();
    ws.insert("cid_integrity".into(), j.weighted.cid_integrity.into_py(py));
    ws.insert("audit_coverage".into(), j.weighted.audit_coverage.into_py(py));
    ws.insert("access_control".into(), j.weighted.access_control.into_py(py));
    ws.insert("evidence_quality".into(), j.weighted.evidence_quality.into_py(py));
    ws.insert("claim_coverage".into(), j.weighted.claim_coverage.into_py(py));
    ws.insert("temporal_freshness".into(), j.weighted.temporal_freshness.into_py(py));
    ws.insert("contradiction_score".into(), j.weighted.contradiction_score.into_py(py));
    ws.insert("source_credibility".into(), j.weighted.source_credibility.into_py(py));
    m.insert("weighted".into(), ws.into_py(py));
    m
}

// ═══════════════════════════════════════════════════════════════
// Agent — shares the Connector's kernel
// ═══════════════════════════════════════════════════════════════

#[pyclass]
#[derive(Clone)]
struct Agent {
    connector: connector_api::Connector,
    kernel: Arc<Mutex<MemoryKernel>>,
    name: String,
    instructions: String,
    compliance: Vec<String>,
    pid: Option<String>,
}

#[pymethods]
impl Agent {
    fn comply(mut slf: PyRefMut<'_, Self>, frameworks: Vec<String>) -> PyRefMut<'_, Self> {
        slf.compliance = frameworks;
        slf
    }

    /// Get or register this agent's PID in the shared kernel.
    fn pid(&mut self) -> PyResult<String> {
        if let Some(ref p) = self.pid {
            return Ok(p.clone());
        }
        let mut k = self.kernel.lock().unwrap();
        let model = self.connector.llm_config().map(|c| c.model.clone());
        let pid = register_and_start(&mut k, &self.name, &format!("ns:{}", self.name), model)
            .map_err(PyRuntimeError::new_err)?;
        self.pid = Some(pid.clone());
        Ok(pid)
    }

    fn run(&mut self, input: &str, user: &str) -> PyResult<PipelineResult> {
        let pipe_id = format!("pipe:{}", self.name);

        // Ensure agent is registered in the shared kernel
        let pid = self.pid()?;

        // Write input
        {
            let mut k = self.kernel.lock().unwrap();
            write_mem(&mut k, &pid, input, user, &pipe_id, PacketType::Input);
        }

        let start = std::time::Instant::now();

        // Call the real LLM
        let response_text = match self.connector.engine_llm_config() {
            Some(mut llm_cfg) => {
                llm_cfg = llm_cfg.with_system(&self.instructions);
                let client = LlmClient::new();
                client.complete_sync(&llm_cfg, input, None)
                    .map(|r| r.text)
                    .unwrap_or_else(|e| format!("[LLM error: {}]", e))
            }
            None => format!("[no LLM configured — agent '{}' echo: {}]", self.name, input),
        };

        // Write LLM response + build output from shared kernel
        let duration_ms = start.elapsed().as_millis() as u64;
        let output = {
            let mut k = self.kernel.lock().unwrap();
            write_mem(&mut k, &pid, &response_text, user, &pipe_id, PacketType::LlmRaw);
            connector_engine::OutputBuilder::build(
                &k, response_text, &pipe_id, 1,
                &self.compliance, duration_ms, Vec::new(),
            )
        };
        Ok(PipelineResult { inner: output })
    }

    fn __repr__(&self) -> String {
        format!("Agent(name='{}', pid={:?})", self.name, self.pid)
    }
}

// ═══════════════════════════════════════════════════════════════
// Pipeline — shares the Connector's kernel
// ═══════════════════════════════════════════════════════════════

#[pyclass]
#[derive(Clone)]
struct PipelineAgent {
    name: String,
    instructions: String,
}

#[pyclass]
#[derive(Clone)]
struct Pipeline {
    connector: connector_api::Connector,
    kernel: Arc<Mutex<MemoryKernel>>,
    name: String,
    agents: Vec<PipelineAgent>,
    route: Option<String>,
    compliance: Vec<String>,
}

#[pymethods]
impl Pipeline {
    fn agent<'a>(mut slf: PyRefMut<'a, Self>, name: &'a str, instructions: &'a str) -> PyRefMut<'a, Self> {
        slf.agents.push(PipelineAgent {
            name: name.to_string(),
            instructions: instructions.to_string(),
        });
        slf
    }

    fn route<'a>(mut slf: PyRefMut<'a, Self>, route: &'a str) -> PyRefMut<'a, Self> {
        slf.route = Some(route.to_string());
        slf
    }

    fn hipaa(mut slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        if !slf.compliance.contains(&"hipaa".into()) { slf.compliance.push("hipaa".into()); }
        slf
    }

    fn soc2(mut slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        if !slf.compliance.contains(&"soc2".into()) { slf.compliance.push("soc2".into()); }
        slf
    }

    fn gdpr(mut slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        if !slf.compliance.contains(&"gdpr".into()) { slf.compliance.push("gdpr".into()); }
        slf
    }

    fn run(&self, input: &str, user: &str) -> PyResult<PipelineResult> {
        let pipe_id = format!("pipe:{}", self.name);
        let model = self.connector.llm_config().map(|c| c.model.clone());
        let llm_cfg = self.connector.engine_llm_config();
        let client = LlmClient::new();
        let start = std::time::Instant::now();
        let mut last_output = input.to_string();

        for agent in &self.agents {
            // Register each pipeline agent in the shared kernel
            let pid = {
                let mut k = self.kernel.lock().unwrap();
                register_and_start(&mut k, &agent.name, &format!("ns:{}", agent.name), model.clone())
                    .map_err(PyRuntimeError::new_err)?
            };

            {
                let mut k = self.kernel.lock().unwrap();
                write_mem(&mut k, &pid, &last_output, user, &pipe_id, PacketType::Input);
            }

            // Call real LLM for each agent
            last_output = match llm_cfg.as_ref() {
                Some(cfg) => {
                    let agent_cfg = cfg.clone().with_system(&agent.instructions);
                    client.complete_sync(&agent_cfg, &last_output, None)
                        .map(|r| r.text)
                        .unwrap_or_else(|e| format!("[LLM error: {}]", e))
                }
                None => format!("[no LLM — {}: {}]", agent.name, last_output),
            };

            {
                let mut k = self.kernel.lock().unwrap();
                write_mem(&mut k, &pid, &last_output, user, &pipe_id, PacketType::LlmRaw);
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let output = {
            let k = self.kernel.lock().unwrap();
            connector_engine::OutputBuilder::build(
                &k, last_output, &pipe_id,
                self.agents.len(), &self.compliance, duration_ms, Vec::new(),
            )
        };
        Ok(PipelineResult { inner: output })
    }

    fn __repr__(&self) -> String {
        let names: Vec<&str> = self.agents.iter().map(|a| a.name.as_str()).collect();
        format!("Pipeline(name='{}', agents=[{}], route='{}')",
            self.name, names.join(", "), self.route.as_deref().unwrap_or("auto"))
    }
}

// ═══════════════════════════════════════════════════════════════
// PipelineResult
// ═══════════════════════════════════════════════════════════════

#[pyclass]
#[derive(Clone)]
struct PipelineResult {
    inner: connector_engine::PipelineOutput,
}

#[pymethods]
impl PipelineResult {
    #[getter]
    fn text(&self) -> String { self.inner.text.clone() }

    #[getter]
    fn trust(&self) -> u32 { self.inner.status.trust }

    #[getter]
    fn trust_grade(&self) -> String { self.inner.status.trust_grade.clone() }

    #[getter]
    fn ok(&self) -> bool { self.inner.status.ok }

    #[getter]
    fn duration_ms(&self) -> u64 { self.inner.status.duration_ms }

    #[getter]
    fn actors(&self) -> usize { self.inner.status.actors }

    #[getter]
    fn steps(&self) -> usize { self.inner.status.steps }

    #[getter]
    fn warnings(&self) -> Vec<String> { self.inner.warnings.clone() }

    #[getter]
    fn errors(&self) -> Vec<String> { self.inner.errors.clone() }

    #[getter]
    fn event_count(&self) -> usize { self.inner.events.len() }

    #[getter]
    fn span_count(&self) -> usize { self.inner.trace.spans.len() }

    #[getter]
    fn trace_id(&self) -> String { self.inner.trace.trace_id.clone() }

    fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.inner.to_json()).unwrap_or_default()
    }

    fn to_otel(&self) -> String {
        serde_json::to_string_pretty(&self.inner.to_otel()).unwrap_or_default()
    }

    fn to_llm(&self) -> String {
        serde_json::to_string_pretty(&self.inner.to_llm_summary()).unwrap_or_default()
    }

    fn provenance(&self) -> String {
        serde_json::to_string_pretty(&self.inner.provenance_summary()).unwrap_or_default()
    }

    fn is_verified(&self) -> bool { self.inner.all_observations_verified() }

    fn __repr__(&self) -> String { format!("{}", self.inner) }
    fn __str__(&self) -> String { format!("{}", self.inner) }
}

// ═══════════════════════════════════════════════════════════════
// Python Module
// ═══════════════════════════════════════════════════════════════

#[pymodule]
fn vac_ffi(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Connector>()?;
    m.add_class::<Agent>()?;
    m.add_class::<Pipeline>()?;
    m.add_class::<PipelineResult>()?;
    Ok(())
}
