//! # Connector Protocols (Ring 3)
//!
//! Protocol bridges that translate external protocol semantics into
//! internal kernel syscalls. Every bridge feeds through the existing
//! security pipeline (AgentFirewall → kernel dispatch → audit).
//!
//! ## Protocols
//!
//! - **MCP Server**: Expose VAC namespaces + ToolBindings as an MCP server (JSON-RPC 2.0)
//! - **MCP Client**: Connect to external MCP servers, discover and proxy tools
//! - **A2A**: Google Agent-to-Agent protocol — Agent Cards, task delegation, SSE
//! - **ACP**: IBM/Linux Foundation async messaging — REST, 202 Accepted, poll
//! - **ANP**: W3C DID-based agent mesh — DID resolution, Ed25519 auth
//! - **AP2**: Google Agent Payment Protocol — cryptographic spending mandates

pub mod error;
pub mod mcp_server;
pub mod mcp_client;
pub mod a2a_bridge;
pub mod acp_bridge;
pub mod anp_bridge;
pub mod ap2_bridge;

pub use error::*;
pub use mcp_server::{McpServer, McpKernelBackend, McpToolDef, McpResourceDef, McpToolResult, McpContent, JsonRpcRequest, JsonRpcResponse, JsonRpcError};
pub use mcp_client::{McpClient, McpTransport, McpBridgeEntry, McpRemoteServer};
pub use a2a_bridge::{A2aBridge, A2aKernelBackend, AgentCard, AgentCapabilities, AgentSkill, A2aTask, TaskState, TaskStatus, TaskSendRequest};
pub use acp_bridge::{AcpBridge, AcpKernelBackend, AcpMessage, AcpMessageStatus, AcpAcceptedResponse, AcpMessageResult};
pub use anp_bridge::{AnpBridge, DidResolver, LocalDidRegistry, DidDocument, AnpRequest, AnpResponse};
pub use ap2_bridge::{PaymentMandate, MandateType, Currency};
