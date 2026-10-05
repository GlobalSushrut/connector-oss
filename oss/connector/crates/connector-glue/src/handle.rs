//! Builder and Handle types for GLUE operations

use crate::cnp::{
    CnpCapabilityContract,
    CnpMessageContract,
    CnpPortContract,
    CnpRouteContract,
    CnpSessionContract,
};
use crate::data::{DataInjection, KnowledgeContract, KnowledgeQuery, MemoryContract};
use crate::infra::{PipelineContract, SecurityContract, ToolContract};
use crate::protocol::{ProtocolAction, ProtocolContract};
use crate::{Glue, GlueResult, GlueError, Noun, runtime};
use std::collections::HashMap;

// =============================================================================
// Verb Builders
// =============================================================================

pub struct RunBuilder {
    pub(crate) glue: Glue,
    pub(crate) target: String,
    pub(crate) inputs: HashMap<String, serde_json::Value>,
    pub(crate) policy: Option<String>,
    pub(crate) timeout_ms: Option<u64>,
}

impl RunBuilder {
    pub fn new(glue: Glue, target: String) -> Self {
        Self { glue, target, inputs: HashMap::new(), policy: None, timeout_ms: None }
    }

    pub fn with_input<K: Into<String>, V: serde::Serialize>(mut self, key: K, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) { self.inputs.insert(key.into(), v); }
        self
    }

    pub fn with_policy<P: Into<String>>(mut self, policy: P) -> Self {
        self.policy = Some(policy.into()); self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self { self.timeout_ms = Some(ms); self }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_run(self.glue, self.target, self.inputs, self.policy)
    }
}

pub struct RememberBuilder {
    pub(crate) glue: Glue,
    pub(crate) key: String,
    pub(crate) content: Option<String>,
    pub(crate) namespace: Option<String>,
    pub(crate) contract: Option<MemoryContract>,
    pub(crate) injection: Option<DataInjection>,
}

impl RememberBuilder {
    pub fn new(glue: Glue, key: String) -> Self {
        Self { glue, key, content: None, namespace: None, contract: None, injection: None }
    }

    pub fn content<C: Into<String>>(mut self, c: C) -> Self { self.content = Some(c.into()); self }
    pub fn namespace<N: Into<String>>(mut self, ns: N) -> Self { self.namespace = Some(ns.into()); self }
    pub fn contract(mut self, contract: MemoryContract) -> Self { self.contract = Some(contract); self }
    pub fn inject(mut self, injection: DataInjection) -> Self { self.injection = Some(injection); self }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_remember(self.glue, self.key, self.content, self.namespace, self.contract, self.injection)
    }
}

pub struct RecallBuilder {
    pub(crate) glue: Glue,
    pub(crate) query: String,
    pub(crate) namespace: Option<String>,
    pub(crate) limit: Option<usize>,
}

impl RecallBuilder {
    pub fn new(glue: Glue, query: String) -> Self {
        Self { glue, query, namespace: None, limit: None }
    }

    pub fn namespace<N: Into<String>>(mut self, ns: N) -> Self { self.namespace = Some(ns.into()); self }
    pub fn limit(mut self, n: usize) -> Self { self.limit = Some(n); self }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_recall(self.glue, self.query, self.namespace, self.limit)
    }
}

pub struct SearchBuilder {
    pub(crate) glue: Glue,
    pub(crate) query: String,
    pub(crate) namespace: Option<String>,
    pub(crate) limit: Option<usize>,
}

impl SearchBuilder {
    pub fn new(glue: Glue, query: String) -> Self {
        Self { glue, query, namespace: None, limit: None }
    }

    pub fn namespace<N: Into<String>>(mut self, ns: N) -> Self { self.namespace = Some(ns.into()); self }
    pub fn limit(mut self, n: usize) -> Self { self.limit = Some(n); self }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_search(self.glue, self.query, self.namespace, self.limit)
    }
}

pub struct ListBuilder {
    pub(crate) glue: Glue,
    pub(crate) noun: Noun,
    pub(crate) namespace: Option<String>,
    pub(crate) limit: Option<usize>,
}

impl ListBuilder {
    pub fn new(glue: Glue, noun: Noun) -> Self {
        Self { glue, noun, namespace: None, limit: None }
    }

    pub fn namespace<N: Into<String>>(mut self, ns: N) -> Self { self.namespace = Some(ns.into()); self }
    pub fn limit(mut self, n: usize) -> Self { self.limit = Some(n); self }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_list(self.glue, self.noun, self.namespace, self.limit)
    }
}

pub struct ShowBuilder {
    pub(crate) glue: Glue,
    pub(crate) noun: Noun,
    pub(crate) target: String,
}

impl ShowBuilder {
    pub fn new(glue: Glue, noun: Noun, target: String) -> Self {
        Self { glue, noun, target }
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_show(self.glue, self.noun, self.target)
    }
}

pub struct AuditBuilder {
    pub(crate) glue: Glue,
    pub(crate) target: String,
}

impl AuditBuilder {
    pub fn new(glue: Glue, target: String) -> Self { Self { glue, target } }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_audit(self.glue, self.target)
    }
}

pub struct VerifyBuilder {
    pub(crate) glue: Glue,
    pub(crate) what: String,
    pub(crate) for_agent: Option<String>,
}

impl VerifyBuilder {
    pub fn new(glue: Glue, what: String) -> Self {
        Self { glue, what, for_agent: None }
    }

    pub fn for_agent<A: Into<String>>(mut self, agent: A) -> Self {
        self.for_agent = Some(agent.into()); self
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_verify(self.glue, self.what, self.for_agent)
    }
}

pub struct SessionBuilder {
    pub(crate) glue: Glue,
    pub(crate) policy: Option<String>,
    pub(crate) namespace: Option<String>,
    pub(crate) timeout_ms: Option<u64>,
}

impl SessionBuilder {
    pub fn new(glue: Glue) -> Self {
        Self { glue, policy: None, namespace: None, timeout_ms: None }
    }

    pub fn policy<P: Into<String>>(mut self, p: P) -> Self { self.policy = Some(p.into()); self }
    pub fn namespace<N: Into<String>>(mut self, ns: N) -> Self { self.namespace = Some(ns.into()); self }
    pub fn timeout_ms(mut self, ms: u64) -> Self { self.timeout_ms = Some(ms); self }

    pub fn build(self) -> crate::GlueSession {
        crate::GlueSession::new(self.glue, self.policy, self.namespace, self.timeout_ms)
    }
}

pub struct KnowledgeIngestBuilder {
    pub(crate) glue: Glue,
    pub(crate) contract: KnowledgeContract,
}

impl KnowledgeIngestBuilder {
    pub fn new(glue: Glue, contract: KnowledgeContract) -> Self {
        Self { glue, contract }
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_knowledge_ingest(self.glue, self.contract)
    }
}

pub struct KnowledgeQueryBuilder {
    pub(crate) glue: Glue,
    pub(crate) namespace: String,
    pub(crate) query: KnowledgeQuery,
}

impl KnowledgeQueryBuilder {
    pub fn new(glue: Glue, namespace: String, query: KnowledgeQuery) -> Self {
        Self { glue, namespace, query }
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_knowledge_query(self.glue, self.namespace, self.query)
    }
}

pub struct ProtocolActionBuilder {
    pub(crate) glue: Glue,
    pub(crate) contract: ProtocolContract,
    pub(crate) action: ProtocolAction,
}

impl ProtocolActionBuilder {
    pub fn new(glue: Glue, contract: ProtocolContract, action: ProtocolAction) -> Self {
        Self { glue, contract, action }
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_protocol_action(self.glue, self.contract, self.action)
    }
}

pub struct PipelineBuilder {
    pub(crate) glue: Glue,
    pub(crate) contract: PipelineContract,
}

impl PipelineBuilder {
    pub fn new(glue: Glue, contract: PipelineContract) -> Self {
        Self { glue, contract }
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        runtime::execute_pipeline(self.glue, self.contract)
    }
}

// =============================================================================
// Resource Handles
// =============================================================================

pub struct AgentHandle {
    glue: Glue,
    name: String,
}

impl AgentHandle {
    pub fn new(glue: Glue, name: String) -> Self { Self { glue, name } }

    pub fn start(self) -> Result<GlueResult, GlueError> { runtime::agent_start(self.glue, self.name) }
    pub fn stop(self) -> Result<GlueResult, GlueError> { runtime::agent_stop(self.glue, self.name) }
    pub fn status(&self) -> Result<GlueResult, GlueError> { runtime::agent_status(self.glue.clone(), self.name.clone()) }
    pub fn pause(self) -> Result<GlueResult, GlueError> { runtime::agent_pause(self.glue, self.name) }
    pub fn resume(self) -> Result<GlueResult, GlueError> { runtime::agent_resume(self.glue, self.name) }
}

pub struct MemoryHandle {
    glue: Glue,
    namespace: String,
}

impl MemoryHandle {
    pub fn new(glue: Glue, namespace: String) -> Self { Self { glue, namespace } }

    pub fn write<C: Into<String>>(self, content: C) -> Result<GlueResult, GlueError> {
        runtime::memory_write(self.glue, self.namespace, content.into())
    }

    pub fn write_with_contract(self, injection: DataInjection, contract: MemoryContract) -> Result<GlueResult, GlueError> {
        runtime::execute_memory_contract_write(self.glue, contract, injection)
    }

    pub fn read(self) -> Result<GlueResult, GlueError> {
        runtime::memory_read(self.glue, self.namespace)
    }

    pub fn range(self, start: usize, end: usize) -> Result<GlueResult, GlueError> {
        runtime::memory_range(self.glue, self.namespace, start, end)
    }
}

pub struct KnowledgeHandle {
    glue: Glue,
    namespace: String,
}

impl KnowledgeHandle {
    pub fn new(glue: Glue, namespace: String) -> Self { Self { glue, namespace } }

    pub fn ingest(self, contract: KnowledgeContract) -> Result<GlueResult, GlueError> {
        runtime::execute_knowledge_ingest(self.glue, contract)
    }

    pub fn query(self, query: KnowledgeQuery) -> Result<GlueResult, GlueError> {
        runtime::execute_knowledge_query(self.glue, self.namespace, query)
    }
}

pub struct ProtocolHandle {
    glue: Glue,
    contract: ProtocolContract,
}

impl ProtocolHandle {
    pub fn new(glue: Glue, contract: ProtocolContract) -> Self { Self { glue, contract } }

    pub fn act(self, action: ProtocolAction) -> Result<GlueResult, GlueError> {
        runtime::execute_protocol_action(self.glue, self.contract, action)
    }
}

pub struct CnpSessionHandle {
    glue: Glue,
    contract: CnpSessionContract,
}

impl CnpSessionHandle {
    pub fn new(glue: Glue, contract: CnpSessionContract) -> Self { Self { glue, contract } }

    pub fn establish(self) -> Result<GlueResult, GlueError> {
        runtime::execute_cnp_session(self.glue, self.contract)
    }
}

pub struct CnpPortHandle {
    glue: Glue,
    contract: CnpPortContract,
}

impl CnpPortHandle {
    pub fn new(glue: Glue, contract: CnpPortContract) -> Self { Self { glue, contract } }

    pub fn open(self) -> Result<GlueResult, GlueError> {
        runtime::execute_cnp_port(self.glue, self.contract)
    }
}

pub struct CnpCapabilityHandle {
    glue: Glue,
    contract: CnpCapabilityContract,
}

impl CnpCapabilityHandle {
    pub fn new(glue: Glue, contract: CnpCapabilityContract) -> Self { Self { glue, contract } }

    pub fn grant(self) -> Result<GlueResult, GlueError> {
        runtime::execute_cnp_capability(self.glue, self.contract)
    }
}

pub struct CnpMessageHandle {
    glue: Glue,
    contract: CnpMessageContract,
}

impl CnpMessageHandle {
    pub fn new(glue: Glue, contract: CnpMessageContract) -> Self { Self { glue, contract } }

    pub fn send(self) -> Result<GlueResult, GlueError> {
        runtime::execute_cnp_message(self.glue, self.contract)
    }
}

pub struct CnpRouteHandle {
    glue: Glue,
    contract: CnpRouteContract,
}

impl CnpRouteHandle {
    pub fn new(glue: Glue, contract: CnpRouteContract) -> Self { Self { glue, contract } }

    pub fn resolve(self) -> Result<GlueResult, GlueError> {
        runtime::execute_cnp_route(self.glue, self.contract)
    }
}

pub struct PipelineHandle {
    glue: Glue,
    contract: PipelineContract,
}

impl PipelineHandle {
    pub fn new(glue: Glue, contract: PipelineContract) -> Self { Self { glue, contract } }

    pub fn run(self) -> Result<GlueResult, GlueError> {
        runtime::execute_pipeline(self.glue, self.contract)
    }
}

pub struct ToolHandle {
    glue: Glue,
    name: String,
}

impl ToolHandle {
    pub fn new(glue: Glue, name: String) -> Self { Self { glue, name } }

    pub fn call(self, params: serde_json::Value) -> Result<GlueResult, GlueError> {
        runtime::tool_call(self.glue, self.name, params)
    }

    pub fn call_with_contract(self, params: serde_json::Value, contract: ToolContract, security: Option<SecurityContract>) -> Result<GlueResult, GlueError> {
        runtime::tool_call_with_contract(self.glue, self.name, params, contract, security)
    }

    pub fn info(&self) -> Result<GlueResult, GlueError> {
        runtime::tool_info(self.glue.clone(), self.name.clone())
    }
}

pub struct PolicyHandle {
    glue: Glue,
    name: String,
}

impl PolicyHandle {
    pub fn new(glue: Glue, name: String) -> Self { Self { glue, name } }

    pub fn bind_to<A: Into<String>>(self, agent: A) -> Result<GlueResult, GlueError> {
        runtime::policy_bind(self.glue, self.name, agent.into())
    }

    pub fn check<A: Into<String>>(self, agent: A) -> Result<GlueResult, GlueError> {
        runtime::policy_check(self.glue, self.name, agent.into())
    }
}
