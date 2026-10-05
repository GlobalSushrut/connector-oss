//! ConnectorError — structured denial errors for every PolicyDecision::Deny.
//!
//! S3 fix (enterprise_dx.md §9 P0): Every rejection must return a machine-readable
//! JSON body with `denial_reason`, `docs_url`, and `audit_cid` so developers can
//! self-serve without reading internal Rust error messages.
//!
//! RFC 9457 Problem Details compliance:
//! - `type`: URI reference identifying the problem type (docs URL)
//! - `title`: Short human-readable summary
//! - `status`: HTTP status code
//! - `detail`: Human-readable explanation specific to this occurrence
//! - `instance`: URI reference identifying the specific occurrence (audit CID)
//!
//! Extensions (Connector-specific):
//! - `hint`: Actionable fix suggestion
//! - `example`: Ready-to-copy code/command
//! - `trace_id`: OpenTelemetry trace ID
//! - `timestamp`: ISO 8601 timestamp

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use opentelemetry::trace::TraceContextExt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// The canonical error body returned by every API denial or error.
///
/// All fields have stable snake_case names that external code can key on.
/// Internal OS-level names (MAC Guard, MemPacket, KECS, BFT) must NEVER appear here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorError {
    /// Machine-readable error code (stable across versions).
    pub error: String,
    /// Human-readable explanation that a developer can act on without reading docs.
    pub human_readable: String,
    /// Why the request was denied.
    pub denial_reason: DenialReason,
    /// The resource that was denied (namespace path or route).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_resource: Option<String>,
    /// The agent's current capability scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_scope: Option<String>,
    /// The agent's current health score (0.0–1.0). Formerly "KECS score".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_health_score: Option<f64>,
    /// CID of the audit entry recording this denial.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_cid: Option<String>,
    /// URL to the documentation page for this specific denial_reason.
    pub docs_url: String,
    /// Actionable hint — what to do right now to fix this (XDX-3).
    /// Rule: if developer opens a second tab to understand this, we failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Ready-to-copy example command or code snippet that resolves the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_fix: Option<String>,
    /// HTTP status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// Stable set of denial reasons. Add new variants here — never break existing ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// Agent tried to access a namespace outside its scope.
    NamespaceBoundary,
    /// Action blocked by access control policy.
    PolicyDenied,
    /// Request rate limit exceeded.
    RateLimitExceeded,
    /// JWT or API key is missing, expired, or invalid.
    AuthenticationRequired,
    /// Agent does not have the required capability grant.
    CapabilityRequired,
    /// Agent's health score is too low to proceed.
    AgentHealthTooLow,
    /// Audit chain integrity check failed.
    AuditChainBroken,
    /// License tier does not include this feature.
    LicenseTierRequired,
    /// License is not active (e.g. past `valid_until`) while `CONNECTOR_LICENSE_ENFORCE=1`.
    LicenseInvalid,
    /// Agent count limit for this license tier reached.
    AgentLimitReached,
    /// Possible prompt injection detected in input.
    InjectionDetected,
    /// Agent is quarantined after a security violation. Requires HITL approval to resume.
    AgentQuarantined,
    /// `CONNECTOR_KERNEL_ENFORCE=1` but the agent has no active host kernel attachment (nft/eBPF stub or real `connector-kerneld`).
    KernelHostNotReady,
    /// Internal server error.
    InternalError,
    /// Resource not found.
    NotFound,
    /// Invalid request body or parameters.
    ValidationError,
    /// LLM failed Connector parameters/rules (DNA + agentic pillars). HTTP 499 — not allowed.
    LlmNotAllowed,
}

impl DenialReason {
    /// Slug used in the docs URL.
    pub fn slug(&self) -> &'static str {
        match self {
            DenialReason::NamespaceBoundary    => "namespace_boundary",
            DenialReason::PolicyDenied         => "policy_denied",
            DenialReason::RateLimitExceeded    => "rate_limit_exceeded",
            DenialReason::AuthenticationRequired => "authentication_required",
            DenialReason::CapabilityRequired   => "capability_required",
            DenialReason::AgentHealthTooLow    => "agent_health_too_low",
            DenialReason::AuditChainBroken     => "audit_chain_broken",
            DenialReason::LicenseTierRequired  => "license_tier_required",
            DenialReason::LicenseInvalid       => "license_invalid",
            DenialReason::AgentLimitReached    => "agent_limit_reached",
            DenialReason::InjectionDetected    => "injection_detected",
            DenialReason::AgentQuarantined     => "agent_quarantined",
            DenialReason::KernelHostNotReady  => "kernel_host_not_ready",
            DenialReason::InternalError        => "internal_error",
            DenialReason::NotFound             => "not_found",
            DenialReason::ValidationError      => "validation_error",
            DenialReason::LlmNotAllowed        => "llm_not_allowed",
        }
    }

    pub fn http_status(&self) -> StatusCode {
        match self {
            DenialReason::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            DenialReason::NotFound               => StatusCode::NOT_FOUND,
            DenialReason::RateLimitExceeded      => StatusCode::TOO_MANY_REQUESTS,
            DenialReason::ValidationError        => StatusCode::UNPROCESSABLE_ENTITY,
            DenialReason::InternalError          => StatusCode::INTERNAL_SERVER_ERROR,
            DenialReason::AgentQuarantined       => {
                // LLM-facing: quarantine surfaces as 499 "not allowed — need human approval"
                StatusCode::from_u16(499).unwrap_or(StatusCode::FORBIDDEN)
            }
            DenialReason::KernelHostNotReady     => StatusCode::FORBIDDEN,
            DenialReason::LicenseInvalid         => StatusCode::FORBIDDEN,
            // Connector semantic: LLM skipped DNA / agentic / rules → not allowed.
            DenialReason::LlmNotAllowed => {
                StatusCode::from_u16(499).unwrap_or(StatusCode::FORBIDDEN)
            }
            _                                    => StatusCode::FORBIDDEN,
        }
    }
}

impl ConnectorError {
    pub fn new(reason: DenialReason, human_readable: impl Into<String>) -> Self {
        let slug = reason.slug();
        ConnectorError {
            error: slug.to_string(),
            human_readable: human_readable.into(),
            docs_url: format!("https://connector.ai/docs/errors/{}", slug),
            denial_reason: reason,
            denied_resource: None,
            agent_scope: None,
            agent_health_score: None,
            audit_cid: None,
            hint: None,
            example_fix: None,
            status: None,
        }
    }

    /// Token budget exhausted — actionable error with reset time and upgrade URL.
    pub fn budget_exhausted(used: u64, limit: u64, reset_at_ms: i64, agent_pid: &str) -> Self {
        Self::new(
            DenialReason::RateLimitExceeded,
            format!(
                "Token budget exhausted ({}/{} tokens). Resets at epoch_ms={}.",
                used, limit, reset_at_ms
            ),
        )
        .with_hint(format!(
            "Increase resources.token_budget.daily_limit in agent.yaml or upgrade tier. \
            Upgrade: https://connector.ai/upgrade"
        ))
        .with_example_fix(format!(
            "# In agent.yaml:\nresources:\n  token_budget:\n    daily_limit: {}\n    # or upgrade at connector.ai/upgrade",
            limit.saturating_mul(10)
        ))
    }

    /// MAC Guard denial — tells developer exactly what to fix.
    pub fn mac_denied(agent_pid: &str, agent_clearance: &str, namespace: &str, ns_level: &str, operation: &str) -> Self {
        Self::new(
            DenialReason::NamespaceBoundary,
            format!(
                "Agent '{}' (clearance: {}) cannot {} namespace '{}' (level: {}). \
                Bell-LaPadula no-{}-up rule enforced.",
                agent_pid, agent_clearance, operation, namespace, ns_level, operation
            ),
        )
        .with_denied_resource(namespace)
        .with_agent_scope(agent_clearance)
        .with_hint(format!(
            "Raise agent clearance to '{}' or use a shared namespace at level ≤ {}.",
            ns_level, agent_clearance
        ))
        .with_example_fix(format!(
            "curl -X POST /api/v1/agents/{}/clearance \\\n  -d '{{\"level\": \"{}\"}}'",
            agent_pid, ns_level
        ))
    }

    /// HIPAA mode without signed BAA.
    pub fn hipaa_no_baa() -> Self {
        Self::new(
            DenialReason::PolicyDenied,
            "HIPAA mode requires a signed Business Associate Agreement (BAA). \
            Without a BAA, processing PHI is a HIPAA violation.".to_string(),
        )
        .with_hint("Sign a BAA at connector.ai/legal/baa (takes 30 seconds), then redeploy.".to_string())
        .with_example_fix("POST /api/v1/legal/baa/accept  # accept BAA, then redeploy with hipaa: true".to_string())
    }

    /// Model not found — lists available models.
    pub fn model_not_found(requested: &str, available: &[&str]) -> Self {
        Self::new(
            DenialReason::ValidationError,
            format!("Model '{}' is not configured. Available in your plan: {}.",
                requested, available.join(", ")),
        )
        .with_hint(format!("Set model: {} in your agent manifest spec.model.name.", available.first().unwrap_or(&"gpt-4o")))
        .with_example_fix(format!("# In agent.yaml:\nspec:\n  model:\n    name: {}", available.first().unwrap_or(&"gpt-4o")))
    }

    pub fn namespace_boundary(agent_ns: &str, denied_ns: &str) -> Self {
        Self::new(
            DenialReason::NamespaceBoundary,
            format!(
                "Your agent is scoped to '{}' but tried to access '{}'. \
                 Update the agent's namespace or request a capability grant via \
                 POST /api/v1/aapi/capabilities/issue.",
                agent_ns, denied_ns
            ),
        )
        .with_denied_resource(denied_ns)
        .with_agent_scope(agent_ns)
    }

    pub fn policy_denied(action: &str, resource: &str) -> Self {
        Self::new(
            DenialReason::PolicyDenied,
            format!(
                "Action '{}' on resource '{}' was denied by an access control policy. \
                 Check POST /api/v1/aapi/policies to see active rules.",
                action, resource
            ),
        )
        .with_denied_resource(resource)
    }

    pub fn auth_required() -> Self {
        Self::new(
            DenialReason::AuthenticationRequired,
            "Request is missing a valid Authorization header. \
             Obtain a JWT via POST /api/v1/auth/token or use an API key from \
             POST /api/v1/auth/api-keys.".to_string(),
        )
    }

    pub fn capability_required(action: &str, resource: &str) -> Self {
        Self::new(
            DenialReason::CapabilityRequired,
            format!(
                "A capability token is required to perform '{}' on '{}'. \
                 Issue one via POST /api/v1/aapi/capabilities/issue.",
                action, resource
            ),
        )
        .with_denied_resource(resource)
    }

    /// LLM skipped Connector DNA / agentic / rules → HTTP 499.
    pub fn llm_not_allowed(domain: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self::new(
            DenialReason::LlmNotAllowed,
            format!(
                "sorry, you are not allowed — need human approval. \
                 Connector rule '{domain}' failed: {detail}."
            ),
        )
        .with_denied_resource(domain)
        .with_hint(
            "Establish agent DNA + agentic pillars, then HITL-approve if required. Quarantine needs human unquarantine.",
        )
    }

    /// Quarantine + HTTP 499 body for LLM/client (same surface as llm_not_allowed).
    pub fn llm_quarantined_need_approval(agent_pid: &str, kind: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self::new(
            DenialReason::LlmNotAllowed,
            format!(
                "sorry, you are not allowed — need human approval. \
                 Agent '{agent_pid}' quarantined ({kind}): {detail}."
            ),
        )
        .with_agent_scope(agent_pid)
        .with_denied_resource("llm.quarantine")
        .with_hint(format!(
            "Approve pending HITL action=unquarantine via POST /api/v1/agents/{agent_pid}/hitl/{{id}}/approve (or Fix queue). Admin force unquarantine is secondary."
        ))
    }

    pub fn agent_health_too_low(score: f64, threshold: f64) -> Self {
        Self::new(
            DenialReason::AgentHealthTooLow,
            format!(
                "Agent health score ({:.2}) is below the deployment threshold ({:.2}). \
                 Review recent audit entries at GET /api/v1/actionlog/denied and \
                 resolve failed operations before retrying.",
                score, threshold
            ),
        )
        .with_agent_health_score(score)
    }

    pub fn injection_detected(score: f64) -> Self {
        Self::new(
            DenialReason::InjectionDetected,
            format!(
                "Possible prompt injection detected in input (score: {:.2}, threshold: 0.75). \
                 Review the input for adversarial instructions and resubmit.",
                score
            ),
        )
    }

    /// Agent quarantined — all actions blocked until HITL review.
    /// LLM/client see HTTP 499: sorry, you are not allowed — need human approval.
    pub fn agent_quarantined(agent_pid: &str, reason: &str, hitl_request_id: Option<&str>) -> Self {
        let mut err = Self::new(
            DenialReason::AgentQuarantined,
            format!(
                "sorry, you are not allowed — need human approval. \
                 Agent '{agent_pid}' is quarantined: {reason}."
            ),
        )
        .with_hint(format!(
            "POST /api/v1/agents/{}/hitl/<request_id>/approve to resume, or /deny to terminate.",
            agent_pid
        ));
        if let Some(id) = hitl_request_id {
            err.example_fix = Some(format!(
                "curl -X POST /api/v1/agents/{}/hitl/{}/approve -H 'Authorization: Bearer <ADMIN_TOKEN>'",
                agent_pid, id
            ));
        }
        err
    }

    pub fn license_required(feature: &str, required_tier: &str) -> Self {
        Self::new(
            DenialReason::LicenseTierRequired,
            format!(
                "'{}' requires {} tier or higher. \
                 Upgrade at https://connector.dev/pricing.",
                feature, required_tier
            ),
        )
    }

    pub fn not_found(resource: &str) -> Self {
        Self::new(
            DenialReason::NotFound,
            format!("'{}' was not found.", resource),
        )
        .with_denied_resource(resource)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(DenialReason::InternalError, msg)
    }

    // ── Builder methods ──────────────────────────────────────────────

    pub fn with_denied_resource(mut self, r: impl Into<String>) -> Self {
        self.denied_resource = Some(r.into());
        self
    }

    pub fn with_agent_scope(mut self, s: impl Into<String>) -> Self {
        self.agent_scope = Some(s.into());
        self
    }

    pub fn with_agent_health_score(mut self, score: f64) -> Self {
        self.agent_health_score = Some(score);
        self
    }

    pub fn with_audit_cid(mut self, cid: impl Into<String>) -> Self {
        self.audit_cid = Some(cid.into());
        self
    }

    pub fn with_hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }

    pub fn with_example_fix(mut self, e: impl Into<String>) -> Self {
        self.example_fix = Some(e.into());
        self
    }

    pub fn http_status(&self) -> StatusCode {
        self.denial_reason.http_status()
    }
}

impl IntoResponse for ConnectorError {
    fn into_response(self) -> Response {
        // In development mode, also print a human-readable denial to stderr
        if std::env::var("CONNECTOR_ENV").as_deref() == Ok("development") {
            eprintln!(
                "[CONNECTOR] Denied ({}): {} | resource={:?} | scope={:?} | hint={:?} | docs={}",
                self.denial_reason.slug(),
                self.human_readable,
                self.denied_resource,
                self.agent_scope,
                self.hint,
                self.docs_url
            );
        }
        let status = self.http_status();
        
        // RFC 9457 Problem Details format
        let problem = self.to_problem_details();
        
        // Wrap in standard {"ok": false, "error": {...}} envelope for SDK compatibility.
        // LLM rule failures / quarantine (HTTP 499) — fixed message the model and clients see.
        let envelope = if matches!(
            self.denial_reason,
            DenialReason::LlmNotAllowed | DenialReason::AgentQuarantined
        ) {
            serde_json::json!({
                "ok": false,
                "status": 499,
                "message": "sorry, you are not allowed — need human approval",
                "error": problem,
                "human_approval": true,
            })
        } else {
            serde_json::json!({
                "ok": false,
                "error": problem,
            })
        };
        
        let mut response = (status, Json(envelope)).into_response();
        // RFC 9457: Content-Type should be application/problem+json
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

/// RFC 9457 Problem Details — industry-standard error format.
/// 
/// This format is understood by API gateways, observability tools, and
/// enterprise integrations (Kong, Apigee, Datadog, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// URI reference identifying the problem type (RFC 9457 §3.1.1)
    #[serde(rename = "type")]
    pub type_: String,
    
    /// Short human-readable summary (RFC 9457 §3.1.2)
    pub title: String,
    
    /// HTTP status code (RFC 9457 §3.1.3)
    pub status: u16,
    
    /// Human-readable explanation specific to this occurrence (RFC 9457 §3.1.4)
    pub detail: String,
    
    /// URI reference identifying the specific occurrence (RFC 9457 §3.1.5)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    
    // ── Connector Extensions ──────────────────────────────────────────────
    
    /// Machine-readable error code (stable across versions)
    pub code: String,
    
    /// Actionable hint — what to do right now to fix this
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    
    /// Ready-to-copy example command or code snippet
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    
    /// The resource that was denied
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    
    /// OpenTelemetry trace ID for correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    
    /// ISO 8601 timestamp
    pub timestamp: String,
}

impl ConnectorError {
    /// Convert to RFC 9457 Problem Details format
    pub fn to_problem_details(&self) -> ProblemDetails {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        
        ProblemDetails {
            type_: self.docs_url.clone(),
            title: self.denial_reason.slug().replace('_', " ").to_string(),
            status: self.http_status().as_u16(),
            detail: self.human_readable.clone(),
            instance: self.audit_cid.clone().map(|cid| format!("urn:connector:audit:{}", cid)),
            code: self.denial_reason.slug().to_string(),
            hint: self.hint.clone(),
            example: self.example_fix.clone(),
            resource: self.denied_resource.clone(),
            trace_id: {
                let cx = tracing::Span::current().context();
                let span = cx.span();
                let sc = span.span_context();
                if sc.is_valid() {
                    Some(format!("{:032x}", sc.trace_id()))
                } else {
                    None
                }
            },
            timestamp: format_iso8601(now_ms),
        }
    }
}

/// Format millisecond timestamp as ISO 8601
fn format_iso8601(ms: i64) -> String {
    let secs = ms / 1000;
    let millis = (ms % 1000) as u32;
    
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    
    let mut year = 1970i64;
    let mut remaining_days = days_since_epoch;
    
    loop {
        let days_in_year = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months: [i64; 12] = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    let mut month = 1;
    for days in days_in_months.iter() {
        if remaining_days < *days {
            break;
        }
        remaining_days -= *days;
        month += 1;
    }
    let day = remaining_days + 1;
    
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, minutes, seconds, millis
    )
}

/// Return a plain `{"ok": false, "error": {"code": ..., "message": ...}}` for
/// handlers that use bare `StatusCode` returns (e.g. debug service 404s).
pub fn error_response(status: axum::http::StatusCode, code: &str, message: &str) -> Response {
    let envelope = serde_json::json!({
        "ok": false,
        "error": {
            "code":    code,
            "message": message,
            "status":  status.as_u16(),
            "docs":    format!("https://connector.ai/docs/errors/{}", code),
        }
    });
    (status, Json(envelope)).into_response()
}

/// Convenience alias used throughout the services.
pub type ApiResult<T> = Result<T, ConnectorError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_boundary_fields() {
        let e = ConnectorError::namespace_boundary("enterprise/hr", "enterprise/finance");
        assert_eq!(e.denial_reason, DenialReason::NamespaceBoundary);
        assert_eq!(e.denied_resource.as_deref(), Some("enterprise/finance"));
        assert_eq!(e.agent_scope.as_deref(), Some("enterprise/hr"));
        assert!(e.docs_url.contains("namespace_boundary"));
    }

    #[test]
    fn test_http_status_mapping() {
        assert_eq!(ConnectorError::auth_required().http_status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ConnectorError::not_found("x").http_status(), StatusCode::NOT_FOUND);
        assert_eq!(
            ConnectorError::policy_denied("read", "resource").http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ConnectorError::llm_not_allowed("dna", "missing genome").http_status().as_u16(),
            499
        );
    }

    #[test]
    fn test_serialization_has_required_fields() {
        let e = ConnectorError::policy_denied("ehr.delete", "ehr:patient-123")
            .with_audit_cid("bafyreiabc123");
        let json = serde_json::to_value(&e).unwrap();
        assert!(json.get("denial_reason").is_some());
        assert!(json.get("docs_url").is_some());
        assert!(json.get("audit_cid").is_some());
        assert!(json.get("human_readable").is_some());
    }
}
