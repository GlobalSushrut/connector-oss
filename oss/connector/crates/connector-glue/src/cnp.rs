use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpPortType {
    MemoryShare,
    ToolDelegate,
    EventStream,
    RequestResponse,
    Broadcast,
    Pipeline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpPortDirection {
    Send,
    Receive,
    Bidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpPortPermission {
    Send,
    Receive,
    SendReceive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpPayloadKind {
    Raw,
    Sensor,
    Actuation,
    Tensor,
    PacketShare,
    ToolGrant,
    Event,
    Request,
    Response,
    PipelineHandoff,
    Cognitive,
    KnowledgeRequest,
    KnowledgeResponse,
    Negotiation,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpRouteStatus {
    Local,
    Forwarded,
    PendingAck,
    Acknowledged,
    Failed,
    DeadLettered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpSessionContract {
    pub local_agent: Option<String>,
    pub remote_agent: String,
    pub remote_cell: Option<String>,
    pub channel_binding: Option<String>,
    pub namespace: Option<String>,
    pub evidence_required: bool,
}

impl CnpSessionContract {
    pub fn new(remote_agent: impl Into<String>) -> Self {
        Self {
            local_agent: None,
            remote_agent: remote_agent.into(),
            remote_cell: None,
            channel_binding: None,
            namespace: None,
            evidence_required: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpPortContract {
    pub id: String,
    pub port_type: CnpPortType,
    pub direction: CnpPortDirection,
    pub owner_agent: Option<String>,
    pub bound_agents: Vec<String>,
    pub max_buffer_size: Option<u32>,
    pub allowed_payload_types: Vec<CnpPayloadKind>,
    pub expires_at_ms: Option<i64>,
}

impl CnpPortContract {
    pub fn new(
        id: impl Into<String>,
        port_type: CnpPortType,
        direction: CnpPortDirection,
    ) -> Self {
        Self {
            id: id.into(),
            port_type,
            direction,
            owner_agent: None,
            bound_agents: Vec::new(),
            max_buffer_size: None,
            allowed_payload_types: Vec::new(),
            expires_at_ms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpCapabilityContract {
    pub port_id: String,
    pub holder_agent: String,
    pub permission: CnpPortPermission,
    pub max_message_size: Option<usize>,
    pub max_messages_per_minute: Option<u32>,
    pub allowed_payload_types: Vec<CnpPayloadKind>,
    pub expires_at_ms: Option<i64>,
    pub delegation_depth: u8,
}

impl CnpCapabilityContract {
    pub fn new(
        port_id: impl Into<String>,
        holder_agent: impl Into<String>,
        permission: CnpPortPermission,
    ) -> Self {
        Self {
            port_id: port_id.into(),
            holder_agent: holder_agent.into(),
            permission,
            max_message_size: None,
            max_messages_per_minute: None,
            allowed_payload_types: Vec::new(),
            expires_at_ms: None,
            delegation_depth: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpMessageContract {
    pub from_agent: Option<String>,
    pub to_agent: String,
    pub session_id: Option<String>,
    pub port_id: Option<String>,
    pub payload_kind: CnpPayloadKind,
    pub body: serde_json::Value,
    pub ttl_ms: Option<i64>,
    pub priority: Option<u8>,
    pub reply_to: Option<String>,
    pub evidence_cid: Option<String>,
    pub trace_id: Option<String>,
    pub metadata: serde_json::Value,
}

impl CnpMessageContract {
    pub fn new(
        to_agent: impl Into<String>,
        payload_kind: CnpPayloadKind,
        body: serde_json::Value,
    ) -> Self {
        Self {
            from_agent: None,
            to_agent: to_agent.into(),
            session_id: None,
            port_id: None,
            payload_kind,
            body,
            ttl_ms: None,
            priority: None,
            reply_to: None,
            evidence_cid: None,
            trace_id: None,
            metadata: serde_json::Value::Object(Default::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpRouteContract {
    pub target_agent: String,
    pub target_cell: Option<String>,
    pub session_id: Option<String>,
    pub sticky: bool,
    pub ack_timeout_ms: Option<i64>,
    pub max_retries: Option<u32>,
    pub expected_status: Option<CnpRouteStatus>,
}

impl CnpRouteContract {
    pub fn new(target_agent: impl Into<String>) -> Self {
        Self {
            target_agent: target_agent.into(),
            target_cell: None,
            session_id: None,
            sticky: true,
            ack_timeout_ms: None,
            max_retries: None,
            expected_status: None,
        }
    }
}
