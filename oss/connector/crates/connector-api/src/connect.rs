//! Connect Module — framework bridges (LangChain, CrewAI, OpenAI Agents, MCP).
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! let pipe = Connector::pipeline("research")
//!     .connect(|c| c
//!         .langchain()
//!         .crewai()
//!         .openai_agents()
//!         .mcp_server(8080)
//!     )
//!     .build();
//! ```

use serde::{Deserialize, Serialize};

/// Framework bridge configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectConfig {
    /// Enable LangChain bridge (expose as tool/memory/retriever)
    pub langchain: bool,
    /// Enable CrewAI bridge (expose as memory backend)
    pub crewai: bool,
    /// Enable OpenAI Agents bridge (expose as tools)
    pub openai_agents: bool,
    /// Enable MCP server (expose as MCP tool server)
    pub mcp_server: Option<McpConfig>,
    /// Enable webhook bridge
    pub webhook: Option<WebhookConfig>,
}

/// MCP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Port to listen on
    pub port: u16,
    /// Host to bind to
    pub host: String,
    /// Exposed tool names (empty = all)
    pub expose_tools: Vec<String>,
}

/// Webhook bridge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL to call on events
    pub url: String,
    /// Events to trigger on
    pub events: Vec<String>,
    /// Secret for HMAC signing
    pub secret: Option<String>,
}

/// Builder for ConnectConfig.
pub struct ConnectBuilder {
    config: ConnectConfig,
}

impl ConnectBuilder {
    pub fn new() -> Self {
        Self {
            config: ConnectConfig::default(),
        }
    }

    /// Enable LangChain bridge.
    pub fn langchain(mut self) -> Self {
        self.config.langchain = true;
        self
    }

    /// Enable CrewAI bridge.
    pub fn crewai(mut self) -> Self {
        self.config.crewai = true;
        self
    }

    /// Enable OpenAI Agents bridge.
    pub fn openai_agents(mut self) -> Self {
        self.config.openai_agents = true;
        self
    }

    /// Enable MCP server on a port.
    pub fn mcp_server(mut self, port: u16) -> Self {
        self.config.mcp_server = Some(McpConfig {
            port,
            host: "0.0.0.0".to_string(),
            expose_tools: Vec::new(),
        });
        self
    }

    /// Enable MCP server with full config.
    pub fn mcp_server_full(mut self, port: u16, host: &str, tools: &[&str]) -> Self {
        self.config.mcp_server = Some(McpConfig {
            port,
            host: host.to_string(),
            expose_tools: tools.iter().map(|s| s.to_string()).collect(),
        });
        self
    }

    /// Enable webhook bridge.
    pub fn webhook(mut self, url: &str, events: &[&str]) -> Self {
        self.config.webhook = Some(WebhookConfig {
            url: url.to_string(),
            events: events.iter().map(|s| s.to_string()).collect(),
            secret: None,
        });
        self
    }

    /// Enable webhook bridge with HMAC secret.
    pub fn webhook_signed(mut self, url: &str, events: &[&str], secret: &str) -> Self {
        self.config.webhook = Some(WebhookConfig {
            url: url.to_string(),
            events: events.iter().map(|s| s.to_string()).collect(),
            secret: Some(secret.to_string()),
        });
        self
    }

    pub fn build(self) -> ConnectConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_builder() {
        let config = ConnectBuilder::new()
            .langchain()
            .crewai()
            .openai_agents()
            .mcp_server(8080)
            .build();

        assert!(config.langchain);
        assert!(config.crewai);
        assert!(config.openai_agents);
        assert_eq!(config.mcp_server.as_ref().unwrap().port, 8080);
    }

    #[test]
    fn test_webhook_bridge() {
        let config = ConnectBuilder::new()
            .webhook_signed("https://hooks.example.com/agent", &["run.complete", "tool.denied"], "secret123")
            .build();

        let wh = config.webhook.unwrap();
        assert_eq!(wh.url, "https://hooks.example.com/agent");
        assert_eq!(wh.events.len(), 2);
        assert_eq!(wh.secret.as_deref(), Some("secret123"));
    }
}
