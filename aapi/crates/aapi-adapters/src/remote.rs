//! Remote Adapter — forwards VAKYA execution to a remote cell.
//!
//! Implements the `Adapter` trait but instead of executing locally,
//! serializes the VAKYA and sends it to a target cell via a bus
//! abstraction. The remote cell executes and returns the result.
//!
//! The bus transport is abstracted behind the `RemoteTransport` trait
//! so that different backends (NATS, in-process, HTTP) can be used.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use aapi_core::Vakya;

use crate::effect::CapturedEffect;
use crate::error::AdapterResult;
use crate::traits::{Adapter, ExecutionContext, ExecutionResult, HealthStatus};

// ============================================================================
// RemoteTransport trait
// ============================================================================

/// Abstraction for sending VAKYA requests to remote cells.
///
/// Implementations may use NATS, HTTP, in-process channels, etc.
#[async_trait]
pub trait RemoteTransport: Send + Sync {
    /// Send a request to a remote cell and wait for a reply.
    async fn request(
        &self,
        cell_id: &str,
        payload: RemoteRequest,
        timeout: Duration,
    ) -> AdapterResult<RemoteResponse>;

    /// Fire-and-forget send (for rollback requests).
    async fn send(&self, cell_id: &str, payload: RemoteRequest) -> AdapterResult<()>;

    /// Health check the transport layer.
    async fn health_check(&self) -> AdapterResult<HealthStatus>;
}

/// Serializable request sent to a remote cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRequest {
    pub request_id: String,
    pub request_type: RemoteRequestType,
    pub vakya: Option<Vakya>,
    pub effect: Option<CapturedEffect>,
    pub context: Option<RemoteContextData>,
}

/// Type of remote request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemoteRequestType {
    Execute,
    Rollback,
    HealthCheck,
}

/// Serializable subset of ExecutionContext for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteContextData {
    pub request_id: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub timeout_ms: Option<u64>,
    pub capture_state: bool,
    pub dry_run: bool,
}

impl From<&ExecutionContext> for RemoteContextData {
    fn from(ctx: &ExecutionContext) -> Self {
        Self {
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            span_id: ctx.span_id.clone(),
            timeout_ms: ctx.timeout_ms,
            capture_state: ctx.capture_state,
            dry_run: ctx.dry_run,
        }
    }
}

/// Serializable response from a remote cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteResponse {
    pub request_id: String,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub effects: Vec<CapturedEffect>,
    pub duration_ms: u64,
}

impl From<RemoteResponse> for ExecutionResult {
    fn from(resp: RemoteResponse) -> Self {
        if resp.success {
            ExecutionResult::success(
                resp.data.unwrap_or(serde_json::Value::Null),
                resp.effects,
                resp.duration_ms,
            )
        } else {
            ExecutionResult::failure(
                resp.error.unwrap_or_else(|| "unknown remote error".into()),
                resp.duration_ms,
            )
        }
    }
}

// ============================================================================
// RemoteAdapter
// ============================================================================

/// Adapter that forwards execution to a remote cell.
pub struct RemoteAdapter {
    /// The target cell ID.
    target_cell_id: String,
    /// The domain this adapter proxies for.
    proxy_domain: String,
    /// Transport for sending requests.
    transport: Box<dyn RemoteTransport>,
    /// Default timeout for remote calls.
    default_timeout: Duration,
}

impl RemoteAdapter {
    pub fn new(
        target_cell_id: impl Into<String>,
        proxy_domain: impl Into<String>,
        transport: Box<dyn RemoteTransport>,
    ) -> Self {
        Self {
            target_cell_id: target_cell_id.into(),
            proxy_domain: proxy_domain.into(),
            transport,
            default_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// The remote cell this adapter forwards to.
    pub fn target_cell(&self) -> &str {
        &self.target_cell_id
    }
}

#[async_trait]
impl Adapter for RemoteAdapter {
    fn domain(&self) -> &str {
        &self.proxy_domain
    }

    fn version(&self) -> &str {
        "1.0.0-remote"
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec![]
    }

    fn supports_action(&self, action: &str) -> bool {
        action.starts_with(&format!("{}.", self.proxy_domain))
    }

    async fn execute(
        &self,
        vakya: &Vakya,
        context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        let timeout = context
            .timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(self.default_timeout);

        let request = RemoteRequest {
            request_id: context.request_id.clone(),
            request_type: RemoteRequestType::Execute,
            vakya: Some(vakya.clone()),
            effect: None,
            context: Some(RemoteContextData::from(context)),
        };

        debug!(
            cell = %self.target_cell_id,
            domain = %self.proxy_domain,
            action = %vakya.v3_kriya.action,
            "Forwarding execution to remote cell"
        );

        let response = self
            .transport
            .request(&self.target_cell_id, request, timeout)
            .await?;

        Ok(ExecutionResult::from(response))
    }

    fn can_rollback(&self, _action: &str) -> bool {
        true
    }

    async fn rollback(&self, effect: &CapturedEffect) -> AdapterResult<()> {
        let request = RemoteRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            request_type: RemoteRequestType::Rollback,
            vakya: None,
            effect: Some(effect.clone()),
            context: None,
        };

        debug!(
            cell = %self.target_cell_id,
            effect_id = %effect.effect_id,
            "Forwarding rollback to remote cell"
        );

        self.transport
            .send(&self.target_cell_id, request)
            .await
    }

    async fn health_check(&self) -> AdapterResult<HealthStatus> {
        self.transport.health_check().await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use aapi_core::types::*;

    /// In-memory mock transport for testing.
    struct MockTransport {
        /// Pre-loaded response (set before constructing the adapter).
        canned_response: Option<RemoteResponse>,
        request_count: AtomicUsize,
        send_count: AtomicUsize,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                canned_response: None,
                request_count: AtomicUsize::new(0),
                send_count: AtomicUsize::new(0),
            }
        }

        fn with_response(mut self, response: RemoteResponse) -> Self {
            self.canned_response = Some(response);
            self
        }
    }

    #[async_trait]
    impl RemoteTransport for MockTransport {
        async fn request(
            &self,
            _cell_id: &str,
            _payload: RemoteRequest,
            _timeout: Duration,
        ) -> AdapterResult<RemoteResponse> {
            self.request_count.fetch_add(1, Ordering::SeqCst);
            if let Some(ref resp) = self.canned_response {
                Ok(resp.clone())
            } else {
                Ok(RemoteResponse {
                    request_id: "default".into(),
                    success: true,
                    data: Some(serde_json::json!({"remote": true})),
                    error: None,
                    effects: vec![],
                    duration_ms: 5,
                })
            }
        }

        async fn send(&self, _cell_id: &str, _payload: RemoteRequest) -> AdapterResult<()> {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn health_check(&self) -> AdapterResult<HealthStatus> {
            Ok(HealthStatus::healthy().with_latency(1))
        }
    }

    fn make_test_vakya() -> Vakya {
        Vakya::builder()
            .karta(aapi_core::vakya::Karta {
                pid: PrincipalId::new("pid:001"),
                role: Some("agent".to_string()),
                realm: None,
                key_id: None,
                actor_type: aapi_core::vakya::ActorType::Agent,
                delegation_chain: vec![],
            })
            .karma(aapi_core::vakya::Karma {
                rid: ResourceId::new("res:test"),
                kind: Some("test".to_string()),
                ns: Some(Namespace::new("test")),
                version: None,
                labels: HashMap::new(),
            })
            .kriya(aapi_core::vakya::Kriya::new("database", "query"))
            .adhikarana(aapi_core::vakya::Adhikarana {
                cap: aapi_core::vakya::CapabilityRef::Reference {
                    cap_ref: "cap:test:all".to_string(),
                },
                policy_ref: None,
                ttl: Some(aapi_core::vakya::TtlConstraint {
                    expires_at: Timestamp(chrono::Utc::now() + chrono::Duration::hours(1)),
                    max_duration_ms: None,
                }),
                budgets: vec![],
                approval_lane: ApprovalLane::None,
                scopes: vec!["*".to_string()],
                context: None,
                delegation_chain_cid: None,
                execution_constraints: None,
                port_id: None,
                required_phase: None,
                required_role: None,
            })
            .build()
            .expect("test vakya")
    }

    #[tokio::test]
    async fn test_remote_adapter_execute() {
        let transport = MockTransport::new();
        let adapter = RemoteAdapter::new("cell-2", "database", Box::new(transport));

        assert_eq!(adapter.domain(), "database");
        assert_eq!(adapter.target_cell(), "cell-2");
        assert!(adapter.supports_action("database.query"));
        assert!(!adapter.supports_action("file.read"));

        let vakya = make_test_vakya();
        let ctx = ExecutionContext::new("req-1");
        let result = adapter.execute(&vakya, &ctx).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_remote_adapter_execute_with_response() {
        let transport = MockTransport::new().with_response(RemoteResponse {
            request_id: "req-1".into(),
            success: true,
            data: Some(serde_json::json!({"rows": 42})),
            error: None,
            effects: vec![],
            duration_ms: 10,
        });

        let adapter = RemoteAdapter::new("cell-2", "database", Box::new(transport));
        let vakya = make_test_vakya();
        let ctx = ExecutionContext::new("req-1");
        let result = adapter.execute(&vakya, &ctx).await.unwrap();

        assert!(result.success);
        assert_eq!(result.data.unwrap()["rows"], 42);
        assert_eq!(result.duration_ms, 10);
    }

    #[tokio::test]
    async fn test_remote_adapter_execute_failure() {
        let transport = MockTransport::new().with_response(RemoteResponse {
            request_id: "req-1".into(),
            success: false,
            data: None,
            error: Some("connection refused".into()),
            effects: vec![],
            duration_ms: 2,
        });

        let adapter = RemoteAdapter::new("cell-2", "database", Box::new(transport));
        let vakya = make_test_vakya();
        let ctx = ExecutionContext::new("req-1");
        let result = adapter.execute(&vakya, &ctx).await.unwrap();

        assert!(!result.success);
        assert_eq!(result.error.unwrap(), "connection refused");
    }

    #[tokio::test]
    async fn test_remote_adapter_rollback() {
        let transport = MockTransport::new();
        let adapter = RemoteAdapter::new("cell-2", "database", Box::new(transport));

        assert!(adapter.can_rollback("database.query"));

        let effect = CapturedEffect::new("v1", EffectBucket::Update, "db:table");
        adapter.rollback(&effect).await.unwrap();
    }

    #[tokio::test]
    async fn test_remote_adapter_health_check() {
        let transport = MockTransport::new();
        let adapter = RemoteAdapter::new("cell-2", "database", Box::new(transport));

        let status = adapter.health_check().await.unwrap();
        assert!(status.healthy);
        assert_eq!(status.latency_ms, Some(1));
    }

    #[tokio::test]
    async fn test_remote_context_conversion() {
        let ctx = ExecutionContext::new("req-42")
            .with_trace("trace-1", "span-1")
            .with_timeout(5000)
            .dry_run();

        let remote_ctx = RemoteContextData::from(&ctx);
        assert_eq!(remote_ctx.request_id, "req-42");
        assert_eq!(remote_ctx.trace_id, Some("trace-1".into()));
        assert_eq!(remote_ctx.span_id, Some("span-1".into()));
        assert_eq!(remote_ctx.timeout_ms, Some(5000));
        assert!(remote_ctx.dry_run);
    }
}
