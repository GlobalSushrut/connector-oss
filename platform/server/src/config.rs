use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default)]
    pub license_key: Option<String>,
    #[serde(default)]
    pub llm: LlmEnvConfig,
    #[serde(default)]
    pub alerts: Vec<AlertRule>,
    #[serde(default)]
    pub cell_id: Option<String>,
    /// Ring 1-4 engine state (audit, secrets, escrow, behavior, etc.)
    /// Env: CONNECTOR_ENGINE_STORAGE=sqlite:./data/engine.db
    /// Default: sqlite:{data_dir}/engine.db
    #[serde(default)]
    pub engine_db: Option<String>,
    /// Ring 0 kernel memory (MemPackets, RangeWindows, agents, SCITT receipts)
    /// Env: CONNECTOR_KERNEL_STORAGE=redb:./data/kernel.redb
    /// Default: redb:{data_dir}/kernel.redb
    #[serde(default)]
    pub kernel_db: Option<String>,

    /// Public base URL as seen by external callers — used in A2A agent card,
    /// webhook callbacks, and Stripe return URLs.
    /// Env: CONNECTOR_PUBLIC_URL=https://api.mycompany.com
    #[serde(default)]
    pub public_url: Option<String>,

    /// Comma-separated CIDR list of trusted reverse proxies for X-Forwarded-For.
    /// Env: CONNECTOR_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
    #[serde(default)]
    pub trusted_proxies: Option<String>,

    /// Port for the dedicated protocol gateway (MCP/A2A/ACP/ANP/AP2).
    /// Set to 0 to disable and keep protocol routes on the main port.
    /// Env: CONNECTOR_PROTOCOL_PORT=9092
    #[serde(default = "default_protocol_port")]
    pub protocol_gateway_port: u16,

    /// Port for the UI-RPC WebSocket gateway.
    /// Set to 0 to disable.
    /// Env: CONNECTOR_UI_RPC_PORT=9093
    #[serde(default = "default_ui_rpc_port")]
    pub ui_rpc_port: u16,
}

fn default_port() -> u16 { 9091 }
fn default_host() -> String { "0.0.0.0".into() }
fn default_data_dir() -> String { "./data".into() }
fn default_protocol_port() -> u16 { 9092 }
fn default_ui_rpc_port() -> u16 { 9093 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmEnvConfig {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub condition: AlertCondition,
    pub channels: Vec<AlertChannel>,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_cooldown() -> u64 { 300 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertCondition {
    #[serde(rename = "trust_below")]
    TrustBelow { threshold: u32 },
    #[serde(rename = "denied_above")]
    DeniedAbove { count: u32, window_secs: u64 },
    #[serde(rename = "integrity_fail")]
    IntegrityFail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertChannel {
    #[serde(rename = "slack")]
    Slack { webhook_url: String },
    #[serde(rename = "pagerduty")]
    PagerDuty { routing_key: String },
    #[serde(rename = "webhook")]
    Webhook { url: String },
}

impl PlatformConfig {
    pub fn from_env() -> Self {
        let data_dir = std::env::var("CONNECTOR_DATA_DIR")
            .unwrap_or_else(|_| "./data".into());
        Self {
            port: std::env::var("CONNECTOR_PORT")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(9091),
            host: std::env::var("CONNECTOR_HOST")
                .unwrap_or_else(|_| "0.0.0.0".into()),
            license_key: std::env::var("CONNECTOR_LICENSE").ok(),
            llm: LlmEnvConfig {
                provider: std::env::var("CONNECTOR_LLM_PROVIDER").ok(),
                model: std::env::var("CONNECTOR_LLM_MODEL").ok(),
                api_key: std::env::var("CONNECTOR_LLM_API_KEY").ok(),
                endpoint: std::env::var("CONNECTOR_LLM_ENDPOINT").ok(),
            },
            alerts: Vec::new(),
            cell_id: std::env::var("CONNECTOR_CELL_ID").ok(),
            public_url: std::env::var("CONNECTOR_PUBLIC_URL").ok(),
            trusted_proxies: std::env::var("CONNECTOR_TRUSTED_PROXIES").ok(),
            protocol_gateway_port: std::env::var("CONNECTOR_PROTOCOL_PORT")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(9092),
            ui_rpc_port: std::env::var("CONNECTOR_UI_RPC_PORT")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(9093),
            engine_db: Some(
                std::env::var("CONNECTOR_ENGINE_STORAGE")
                    .unwrap_or_else(|_| format!("sqlite:{}/engine.db", data_dir))
            ),
            kernel_db: Some(
                std::env::var("CONNECTOR_KERNEL_STORAGE")
                    .unwrap_or_else(|_| format!("redb:{}/kernel.redb", data_dir))
            ),
            data_dir,
        }
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn protocol_gateway_addr(&self) -> std::net::SocketAddr {
        format!("{}:{}", self.host, self.protocol_gateway_port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:9092".parse().unwrap())
    }

    pub fn ui_rpc_addr(&self) -> std::net::SocketAddr {
        format!("{}:{}", self.host, self.ui_rpc_port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:9093".parse().unwrap())
    }

    /// The public-facing URL for this node (used in callbacks, agent card, etc.)
    pub fn public_url(&self) -> String {
        self.public_url.clone()
            .unwrap_or_else(|| format!("http://localhost:{}", self.port))
    }

    /// Resolved SQLite path for Ring 1-4 engine state.
    pub fn engine_db_uri(&self) -> String {
        self.engine_db.clone()
            .unwrap_or_else(|| format!("sqlite:{}/engine.db", self.data_dir))
    }

    /// Resolved redb path for Ring 0 kernel memory.
    pub fn kernel_db_uri(&self) -> String {
        self.kernel_db.clone()
            .unwrap_or_else(|| format!("redb:{}/kernel.redb", self.data_dir))
    }

    pub fn db_path(&self) -> String {
        format!("{}/connector.db", self.data_dir)
    }
}
