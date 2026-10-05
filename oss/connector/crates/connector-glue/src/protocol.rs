//! Protocol contracts for GLUE.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Mcp,
    A2a,
    Acp,
    Anp,
    Ap2,
    Cnp,
}

impl ProtocolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::A2a => "a2a",
            Self::Acp => "acp",
            Self::Anp => "anp",
            Self::Ap2 => "ap2",
            Self::Cnp => "cnp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolMode {
    Client,
    Server,
    Bridge,
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolContract {
    pub kind: ProtocolKind,
    pub mode: ProtocolMode,
    pub endpoint: Option<String>,
    pub namespace: Option<String>,
    pub agent: Option<String>,
    pub capability: Option<String>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl ProtocolContract {
    pub fn new(kind: ProtocolKind, mode: ProtocolMode) -> Self {
        Self {
            kind,
            mode,
            endpoint: None,
            namespace: None,
            agent: None,
            capability: None,
            metadata: serde_json::Map::new(),
        }
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = Some(agent.into());
        self
    }

    pub fn capability(mut self, capability: impl Into<String>) -> Self {
        self.capability = Some(capability.into());
        self
    }

    pub fn meta<V: Serialize>(mut self, key: impl Into<String>, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.metadata.insert(key.into(), v);
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolAction {
    McpDiscover {
        server_url: String,
        timeout_secs: Option<u64>,
    },
    McpCall {
        server_url: String,
        tool_name: String,
        arguments: serde_json::Value,
    },
    McpServe {
        method: String,
        params: serde_json::Value,
    },
    A2aCard,
    A2aSendTask {
        task_id: String,
        message: serde_json::Value,
        session_id: Option<String>,
    },
    A2aGetTask {
        task_id: String,
    },
    A2aCancelTask {
        task_id: String,
    },
    AcpSendMessage {
        message_id: String,
        sender: String,
        recipient: String,
        content: serde_json::Value,
    },
    AcpGetMessageStatus {
        message_id: String,
    },
    AnpRegisterDid {
        did: String,
        service_endpoint: String,
    },
    AnpResolveDid {
        did: String,
    },
    Ap2CreateMandate {
        payer: String,
        payee: String,
        amount: f64,
        currency: String,
    },
    Ap2GetMandate {
        mandate_id: String,
    },
    CnpEstablishSession {
        peer_agent: String,
    },
    CnpSend {
        to: String,
        payload: serde_json::Value,
    },
    CnpReceive {
        agent: String,
    },
}

impl ProtocolAction {
    pub fn kind(&self) -> ProtocolKind {
        match self {
            Self::McpDiscover { .. } | Self::McpCall { .. } | Self::McpServe { .. } => ProtocolKind::Mcp,
            Self::A2aCard | Self::A2aSendTask { .. } | Self::A2aGetTask { .. } | Self::A2aCancelTask { .. } => ProtocolKind::A2a,
            Self::AcpSendMessage { .. } | Self::AcpGetMessageStatus { .. } => ProtocolKind::Acp,
            Self::AnpRegisterDid { .. } | Self::AnpResolveDid { .. } => ProtocolKind::Anp,
            Self::Ap2CreateMandate { .. } | Self::Ap2GetMandate { .. } => ProtocolKind::Ap2,
            Self::CnpEstablishSession { .. } | Self::CnpSend { .. } | Self::CnpReceive { .. } => ProtocolKind::Cnp,
        }
    }

    pub fn verb(&self) -> &'static str {
        match self {
            Self::McpDiscover { .. } => "discover",
            Self::McpCall { .. } => "call",
            Self::McpServe { .. } => "serve",
            Self::A2aCard => "show",
            Self::A2aSendTask { .. } => "send",
            Self::A2aGetTask { .. } => "show",
            Self::A2aCancelTask { .. } => "cancel",
            Self::AcpSendMessage { .. } => "send",
            Self::AcpGetMessageStatus { .. } => "show",
            Self::AnpRegisterDid { .. } => "bind",
            Self::AnpResolveDid { .. } => "show",
            Self::Ap2CreateMandate { .. } => "create",
            Self::Ap2GetMandate { .. } => "show",
            Self::CnpEstablishSession { .. } => "connect",
            Self::CnpSend { .. } => "send",
            Self::CnpReceive { .. } => "receive",
        }
    }
}
