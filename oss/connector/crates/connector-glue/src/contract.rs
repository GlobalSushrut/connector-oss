//! CompiledContract - CLS contract representation

use crate::cnp::{
    CnpCapabilityContract,
    CnpMessageContract,
    CnpPortContract,
    CnpRouteContract,
    CnpSessionContract,
};
use crate::data::{KnowledgeContract, MemoryContract};
use crate::infra::{PipelineContract, SecurityContract, ToolContract};
use crate::protocol::ProtocolContract;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A compiled CLS contract ready for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledContract {
    /// Contract CID (content-addressed identifier)
    pub cid: String,
    /// Contract name
    pub name: String,
    /// Contract version
    pub version: Option<String>,
    /// Contract source (for debugging)
    pub source: Option<String>,
    /// Input parameters
    pub inputs: Vec<ParamDef>,
    /// Output parameters
    pub outputs: Vec<ParamDef>,
    /// Required tools
    pub tools: Vec<String>,
    /// Required memory contracts
    pub memory_contracts: Vec<MemoryContract>,
    /// Required knowledge contracts
    pub knowledge_contracts: Vec<KnowledgeContract>,
    /// Required protocol contracts
    pub protocol_contracts: Vec<ProtocolContract>,
    /// Required native CNP session contracts
    pub cnp_session_contracts: Vec<CnpSessionContract>,
    /// Required native CNP port contracts
    pub cnp_port_contracts: Vec<CnpPortContract>,
    /// Required native CNP capability contracts
    pub cnp_capability_contracts: Vec<CnpCapabilityContract>,
    /// Required native CNP message contracts
    pub cnp_message_contracts: Vec<CnpMessageContract>,
    /// Required native CNP route contracts
    pub cnp_route_contracts: Vec<CnpRouteContract>,
    /// Required pipeline contracts
    pub pipeline_contracts: Vec<PipelineContract>,
    /// Required tool contracts
    pub tool_contracts: Vec<ToolContract>,
    /// Required security posture
    pub security_contract: Option<SecurityContract>,
    /// Required capabilities
    pub capabilities: Vec<String>,
    /// Required policies
    pub policies: Vec<String>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDef {
    pub name: String,
    pub type_name: String,
    pub required: bool,
    pub description: Option<String>,
}

impl CompiledContract {
    pub fn new(cid: String, name: String) -> Self {
        Self {
            cid,
            name,
            version: None,
            source: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            tools: Vec::new(),
            memory_contracts: Vec::new(),
            knowledge_contracts: Vec::new(),
            protocol_contracts: Vec::new(),
            cnp_session_contracts: Vec::new(),
            cnp_port_contracts: Vec::new(),
            cnp_capability_contracts: Vec::new(),
            cnp_message_contracts: Vec::new(),
            cnp_route_contracts: Vec::new(),
            pipeline_contracts: Vec::new(),
            tool_contracts: Vec::new(),
            security_contract: None,
            capabilities: Vec::new(),
            policies: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    pub fn with_input(mut self, name: &str, type_name: &str, required: bool) -> Self {
        self.inputs.push(ParamDef {
            name: name.to_string(),
            type_name: type_name.to_string(),
            required,
            description: None,
        });
        self
    }

    pub fn with_output(mut self, name: &str, type_name: &str) -> Self {
        self.outputs.push(ParamDef {
            name: name.to_string(),
            type_name: type_name.to_string(),
            required: true,
            description: None,
        });
        self
    }

    pub fn with_tool(mut self, tool: &str) -> Self {
        self.tools.push(tool.to_string());
        self
    }

    pub fn with_memory_contract(mut self, contract: MemoryContract) -> Self {
        self.memory_contracts.push(contract);
        self
    }

    pub fn with_knowledge_contract(mut self, contract: KnowledgeContract) -> Self {
        self.knowledge_contracts.push(contract);
        self
    }

    pub fn with_protocol_contract(mut self, contract: ProtocolContract) -> Self {
        self.protocol_contracts.push(contract);
        self
    }

    pub fn with_cnp_session_contract(mut self, contract: CnpSessionContract) -> Self {
        self.cnp_session_contracts.push(contract);
        self
    }

    pub fn with_cnp_port_contract(mut self, contract: CnpPortContract) -> Self {
        self.cnp_port_contracts.push(contract);
        self
    }

    pub fn with_cnp_capability_contract(mut self, contract: CnpCapabilityContract) -> Self {
        self.cnp_capability_contracts.push(contract);
        self
    }

    pub fn with_cnp_message_contract(mut self, contract: CnpMessageContract) -> Self {
        self.cnp_message_contracts.push(contract);
        self
    }

    pub fn with_cnp_route_contract(mut self, contract: CnpRouteContract) -> Self {
        self.cnp_route_contracts.push(contract);
        self
    }

    pub fn with_pipeline_contract(mut self, contract: PipelineContract) -> Self {
        self.pipeline_contracts.push(contract);
        self
    }

    pub fn with_tool_contract(mut self, contract: ToolContract) -> Self {
        self.tool_contracts.push(contract);
        self
    }

    pub fn with_security_contract(mut self, contract: SecurityContract) -> Self {
        self.security_contract = Some(contract);
        self
    }

    pub fn with_policy(mut self, policy: &str) -> Self {
        self.policies.push(policy.to_string());
        self
    }
}
