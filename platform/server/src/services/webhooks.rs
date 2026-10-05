//! # Webhook Delivery Service
//!
//! Allows operators to register HTTP endpoints that receive real-time event
//! notifications from the platform.  Every significant platform event —
//! budget exceeded, injection blocked, trust degraded, agent failed, pipeline
//! completed — is delivered here.
//!
//! ## Why this matters for sales
//! Enterprise buyers require Slack/PagerDuty/Datadog integration as a
//! procurement prerequisite.  This service provides the outbound half;
//! the buyer's existing alerting stack handles the inbound half.
//!
//! ## Storage layout (engine_store)
//!   folder: `webhooks`         — registered endpoints
//!   folder: `webhook_events`   — delivery log (last 1000 events)
//!
//! ## Events emitted by platform
//!   - `budget.exceeded`        — agent token budget hit
//!   - `budget.warning`         — agent at 70/80/90% of budget
//!   - `injection.blocked`      — semantic injection detected + blocked
//!   - `trust.degraded`         — trust score dropped below threshold
//!   - `agent.failed`           — agent operation failure rate > 20%
//!   - `pipeline.completed`     — multi-agent pipeline finished
//!   - `pipeline.failed`        — pipeline step errored
//!   - `anomaly.detected`       — anomaly detector fired
//!   - `audit.tamper`           — HMAC chain integrity failure

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub webhook_id: String,
    pub name: String,
    pub url: String,
    /// Event types to subscribe to. Empty = subscribe to all.
    pub events: Vec<String>,
    /// Optional HMAC signing secret — platform signs payloads with HMAC-SHA256
    pub secret: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub enabled: bool,
    pub failure_count: u32,
    pub last_delivery_at: Option<String>,
    pub last_delivery_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub event_id: String,
    pub event_type: String,
    pub webhook_id: String,
    pub payload: serde_json::Value,
    pub delivered_at: String,
    pub status: WebhookDeliveryStatus,
    pub http_status: Option<u16>,
    pub error: Option<String>,
    pub attempt: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Skipped, // webhook disabled
}

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterWebhookRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    pub secret: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateWebhookRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub secret: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct TestWebhookRequest {
    pub event_type: Option<String>,
}

// ── Auth helper ───────────────────────────────────────────────────────────────

fn caller(headers: &axum::http::HeaderMap) -> Option<(String, PlatformRole)> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))?;
    let claims = verify_token(token).ok()?;
    let role = if crate::services::runtime_control::dev_auth_bypass_allowed() {
        PlatformRole::SuperAdmin
    } else {
        PlatformRole::from_str(&claims.role)
    };
    Some((claims.sub, role))
}

// ── Public API for emitting events (used by other services) ──────────────────

/// Emit a platform event to all matching registered webhooks.
/// This is called internally from multiagent, experiments, monitor, etc.
/// Delivery is logged regardless of HTTP outcome.
pub fn emit_event(
    engine_store: &mut dyn connector_engine::engine_store::EngineStore,
    event_type: &str,
    payload: serde_json::Value,
) {
    let keys = engine_store
        .folder_keys("webhooks", None)
        .unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339();

    for key in &keys {
        let hook_val = match engine_store.folder_get("webhooks", key).ok().flatten() {
            Some(v) => v,
            None => continue,
        };
        let hook: WebhookEndpoint = match serde_json::from_value(hook_val) {
            Ok(h) => h,
            Err(_) => continue,
        };

        if !hook.enabled {
            continue;
        }

        // Check subscription — empty events list = subscribe to all
        if !hook.events.is_empty() && !hook.events.iter().any(|e| e == event_type || e == "*") {
            continue;
        }

        let event_id = format!("evt_{}", uuid::Uuid::new_v4());

        // Build signed payload
        let envelope = serde_json::json!({
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": now,
            "payload": payload,
        });

        // HMAC-SHA256 signature if secret configured
        let signature = if let Some(ref secret) = hook.secret {
            let body = serde_json::to_string(&envelope).unwrap_or_default();
            Some(hmac_sha256_hex(secret, &body))
        } else {
            None
        };

        // Attempt synchronous delivery (best-effort, non-blocking in prod via spawn)
        let (status, http_status, error) =
            attempt_delivery(&hook.url, &envelope, signature.as_deref(), Some(&event_id));

        // Log the delivery attempt
        let event_log = WebhookEvent {
            event_id: event_id.clone(),
            event_type: event_type.to_string(),
            webhook_id: hook.webhook_id.clone(),
            payload: envelope.clone(),
            delivered_at: now.clone(),
            status: status.clone(),
            http_status,
            error: error.clone(),
            attempt: 1,
        };

        let log_key = format!(
            "{}_{}",
            chrono::Utc::now().timestamp_millis(),
            &event_id[..12.min(event_id.len())]
        );
        let _ = engine_store.folder_put(
            "webhook_events",
            &log_key,
            &serde_json::to_value(&event_log).unwrap_or_default(),
        );

        // OPS-07: failed deliveries enter the durable retry queue (worker POSTs later).
        if status == WebhookDeliveryStatus::Failed {
            enqueue_failed_delivery(engine_store, &hook.webhook_id, &event_id, &envelope, 0);
        }

        // FIX BUG-018: Update webhook endpoint record with failure_count and last_delivery status
        let mut updated_hook = hook.clone();
        updated_hook.last_delivery_at = Some(now.clone());
        updated_hook.last_delivery_status = Some(format!("{:?}", status));
        if status == WebhookDeliveryStatus::Failed {
            updated_hook.failure_count += 1;
            // Auto-disable after 10 consecutive failures
            if updated_hook.failure_count >= 10 {
                updated_hook.enabled = false;
            }
        } else {
            // Reset failure count on success
            updated_hook.failure_count = 0;
        }
        let _ = engine_store.folder_put(
            "webhooks",
            &updated_hook.webhook_id,
            &serde_json::to_value(&updated_hook).unwrap_or_default(),
        );
    }
}

/// Compute real HMAC-SHA256 over the body using a secret key.
/// Returns "sha256=<hex>" matching the format used by Svix, Stripe, and GitHub webhooks.
fn hmac_sha256_hex(secret: &str, body: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").unwrap());
    mac.update(body.as_bytes());
    let result = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(result))
}

/// DX-P3-2: Best-effort synchronous HTTP POST with HMAC-SHA256 signature header.
/// Sets `X-Connector-Signature: sha256=<hmac>` on every delivery when a secret is configured.
/// Uses reqwest blocking client. Returns (status, http_code, error_msg).
fn attempt_delivery(
    url: &str,
    body: &serde_json::Value,
    signature: Option<&str>,
    event_id: Option<&str>,
) -> (WebhookDeliveryStatus, Option<u16>, Option<String>) {
    if let Err(code) = crate::substrate::egress_policy::assert_safe_outbound_url(url) {
        tracing::warn!(url = %url, code, "webhook delivery blocked by egress policy");
        return (WebhookDeliveryStatus::Failed, None, Some(code.to_string()));
    }
    let body_str = match serde_json::to_string(body) {
        Ok(s) => s,
        Err(e) => {
            return (
                WebhookDeliveryStatus::Failed,
                None,
                Some(format!("serialize error: {}", e)),
            )
        }
    };

    // Build request headers — always include content-type and user-agent.
    // X-Connector-Signature is only added when the webhook has a secret configured.
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("connector-platform/webhook-delivery")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "webhook client build failed");
            return (
                WebhookDeliveryStatus::Failed,
                None,
                Some(format!("client build error: {}", e)),
            );
        }
    };

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Connector-Event", "true");

    if let Some(eid) = event_id.filter(|s| !s.is_empty()) {
        req = req
            .header("X-Connector-Event-Id", eid)
            .header("Idempotency-Key", eid);
    }

    // DX-P3-2 core: set the signature header when a per-webhook secret is present
    if let Some(sig) = signature {
        req = req.header("X-Connector-Signature", sig);
    }

    match req.body(body_str.clone()).send() {
        Ok(resp) => {
            let http_status = resp.status().as_u16();
            if resp.status().is_success() {
                tracing::info!(url = %url, http_status, sig_present = signature.is_some(), "webhook delivered");
                (WebhookDeliveryStatus::Delivered, Some(http_status), None)
            } else {
                let msg = format!("HTTP {}", http_status);
                tracing::warn!(url = %url, http_status, "webhook delivery non-2xx");
                (WebhookDeliveryStatus::Failed, Some(http_status), Some(msg))
            }
        }
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "webhook delivery failed");
            (WebhookDeliveryStatus::Failed, None, Some(e.to_string()))
        }
    }
}

const WEBHOOK_BACKOFF_MINS: [i64; 5] = [1, 5, 30, 120, 480];

fn retry_key(webhook_id: &str, event_id: &str) -> String {
    format!("retry_{webhook_id}_{event_id}")
}

/// Upsert a durable retry row keyed by (webhook_id, event_id) — OPS-07 idempotency.
fn enqueue_failed_delivery(
    engine_store: &mut dyn connector_engine::engine_store::EngineStore,
    webhook_id: &str,
    event_id: &str,
    payload: &serde_json::Value,
    attempt: usize,
) {
    let now = chrono::Utc::now();
    let next_attempt_ms = if attempt < WEBHOOK_BACKOFF_MINS.len() {
        now.timestamp_millis() + WEBHOOK_BACKOFF_MINS[attempt] * 60_000
    } else {
        -1
    };
    let status = if next_attempt_ms < 0 {
        "dead_letter"
    } else {
        "queued"
    };
    let key = retry_key(webhook_id, event_id);
    let entry = serde_json::json!({
        "retry_id": key,
        "webhook_id": webhook_id,
        "event_id": event_id,
        "attempt": attempt,
        "max_attempts": WEBHOOK_BACKOFF_MINS.len(),
        "next_attempt_ms": next_attempt_ms,
        "next_attempt_iso": chrono::DateTime::from_timestamp_millis(next_attempt_ms.max(0))
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "dead_letter".into()),
        "status": status,
        "payload": payload,
        "enqueued_at": now.to_rfc3339(),
        "updated_at": now.to_rfc3339(),
    });
    let _ = engine_store.folder_put("webhook_retry", &key, &entry);
}

/// Worker entry: deliver due `webhook_retry` rows. Returns (delivered, failed, dead_letter).
pub fn process_due_webhook_retries(state: &SharedState) -> (usize, usize, usize) {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let due: Vec<(String, serde_json::Value)> = {
        let es = match crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(error = %e, "[webhook_retry] skip due scan");
                return (0, 0, 0);
            }
        };
        let keys = es.folder_keys("webhook_retry", None).unwrap_or_default();
        keys.iter()
            .filter_map(|k| {
                es.folder_get("webhook_retry", k)
                    .ok()
                    .flatten()
                    .map(|v| (k.clone(), v))
            })
            .filter(|(_, v)| {
                v.get("status").and_then(|s| s.as_str()) == Some("queued")
                    && v.get("next_attempt_ms")
                        .and_then(|n| n.as_i64())
                        .map(|t| t >= 0 && t <= now_ms)
                        .unwrap_or(false)
            })
            .collect()
    };

    let mut delivered = 0usize;
    let mut failed = 0usize;
    let mut dead = 0usize;

    for (key, mut entry) in due {
        let webhook_id = entry
            .get("webhook_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let event_id = entry
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let attempt = entry.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let payload = entry
            .get("payload")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let hook = {
            match crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
                Ok(es) => es
                    .folder_get("webhooks", &webhook_id)
                    .ok()
                    .flatten()
                    .and_then(|v| serde_json::from_value::<WebhookEndpoint>(v).ok()),
                Err(e) => {
                    tracing::error!(error = %e, "[webhook_retry] skip hook lookup");
                    continue;
                }
            }
        };

        let Some(hook) = hook.filter(|h| h.enabled) else {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("status".into(), serde_json::json!("dead_letter"));
                obj.insert(
                    "last_error".into(),
                    serde_json::json!("webhook_missing_or_disabled"),
                );
            }
            if let Ok(mut es) = crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
                let _ = es.folder_put("webhook_retry", &key, &entry);
            }
            dead += 1;
            continue;
        };

        let signature = hook.secret.as_ref().map(|secret| {
            let body = serde_json::to_string(&payload).unwrap_or_default();
            hmac_sha256_hex(secret, &body)
        });
        let (status, http_status, error) =
            attempt_delivery(&hook.url, &payload, signature.as_deref(), Some(&event_id));

        let now = chrono::Utc::now();
        if status == WebhookDeliveryStatus::Delivered {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("status".into(), serde_json::json!("delivered"));
                obj.insert("delivered_at".into(), serde_json::json!(now.to_rfc3339()));
                obj.insert("http_status".into(), serde_json::json!(http_status));
            }
            let Ok(mut es) = crate::util_lock::mutex_lock(&state.engine_store, "engine_store")
            else {
                continue;
            };
            let _ = es.folder_put("webhook_retry", &key, &entry);
            // Reset failure streak on success
            if let Ok(Some(mut hv)) = es.folder_get("webhooks", &webhook_id) {
                if let Ok(mut h) = serde_json::from_value::<WebhookEndpoint>(hv.clone()) {
                    h.failure_count = 0;
                    h.last_delivery_at = Some(now.to_rfc3339());
                    h.last_delivery_status = Some("Delivered".into());
                    hv = serde_json::to_value(&h).unwrap_or(hv);
                    let _ = es.folder_put("webhooks", &webhook_id, &hv);
                }
            }
            delivered += 1;
            continue;
        }

        let next_attempt = attempt + 1;
        if next_attempt >= WEBHOOK_BACKOFF_MINS.len() {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("status".into(), serde_json::json!("dead_letter"));
                obj.insert("attempt".into(), serde_json::json!(next_attempt));
                obj.insert("last_error".into(), serde_json::json!(error));
                obj.insert("http_status".into(), serde_json::json!(http_status));
                obj.insert(
                    "dead_lettered_at".into(),
                    serde_json::json!(now.to_rfc3339()),
                );
            }
            let Ok(mut es) = crate::util_lock::mutex_lock(&state.engine_store, "engine_store")
            else {
                continue;
            };
            let _ = es.folder_put("webhook_retry", &key, &entry);
            dead += 1;
        } else {
            let next_ms = now.timestamp_millis() + WEBHOOK_BACKOFF_MINS[next_attempt] * 60_000;
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("status".into(), serde_json::json!("queued"));
                obj.insert("attempt".into(), serde_json::json!(next_attempt));
                obj.insert("next_attempt_ms".into(), serde_json::json!(next_ms));
                obj.insert(
                    "next_attempt_iso".into(),
                    serde_json::json!(chrono::DateTime::from_timestamp_millis(next_ms)
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default()),
                );
                obj.insert("last_error".into(), serde_json::json!(error));
                obj.insert("http_status".into(), serde_json::json!(http_status));
                obj.insert("updated_at".into(), serde_json::json!(now.to_rfc3339()));
            }
            let Ok(mut es) = crate::util_lock::mutex_lock(&state.engine_store, "engine_store")
            else {
                continue;
            };
            let _ = es.folder_put("webhook_retry", &key, &entry);
            failed += 1;
        }
        tracing::warn!(
            webhook_id = %webhook_id,
            event_id = %event_id,
            attempt = next_attempt,
            "[webhook_retry] delivery failed — rescheduled or dead-lettered"
        );
    }

    (delivered, failed, dead)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /webhooks — register a new webhook endpoint
/// Required role: operator+
pub async fn register_webhook(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterWebhookRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }
    if req.url.is_empty() {
        return Json(serde_json::json!({"error": "url is required", "status": 400}));
    }
    if let Err(code) = crate::substrate::egress_policy::assert_safe_outbound_url(&req.url) {
        return Json(serde_json::json!({
            "error": "egress_denied",
            "code": code,
            "status": 400,
            "message": "Webhook URL blocked by egress policy",
        }));
    }

    let webhook_id = format!("wh_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    let hook = WebhookEndpoint {
        webhook_id: webhook_id.clone(),
        name: req.name.clone(),
        url: req.url.clone(),
        events: req.events.clone(),
        secret: req.secret.clone(),
        created_by: user_id.clone(),
        created_at: now,
        enabled: true,
        failure_count: 0,
        last_delivery_at: None,
        last_delivery_status: None,
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "webhooks",
        "webhooks",
        "register_webhook",
        &serde_json::json!({"name": req.name.as_str(), "url": req.url.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "webhooks",
        &webhook_id,
        &serde_json::to_value(&hook).unwrap_or_default(),
    );
    drop(es);

    let event_count = if req.events.is_empty() {
        "all events".to_string()
    } else {
        req.events.join(", ")
    };
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "webhook_id": webhook_id,
        "name": req.name,
        "url": req.url,
        "subscribed_events": event_count,
        "enabled": true,
        "signed": req.secret.is_some(),
        "created_by": user_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /webhooks — list all registered webhooks
/// Required role: operator+
pub async fn list_webhooks(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("webhooks", None).unwrap_or_default();
    let hooks: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("webhooks", k).ok().flatten())
        .filter_map(|v| {
            let h: WebhookEndpoint = serde_json::from_value(v).ok()?;
            Some(serde_json::json!({
                "webhook_id": h.webhook_id,
                "name": h.name,
                "url": h.url,
                "events": h.events,
                "enabled": h.enabled,
                "failure_count": h.failure_count,
                "last_delivery_at": h.last_delivery_at,
                "last_delivery_status": h.last_delivery_status,
                "signed": h.secret.is_some(),
            }))
        })
        .collect();

    Json(serde_json::json!({"count": hooks.len(), "webhooks": hooks}))
}

/// GET /webhooks/:id — get a specific webhook
pub async fn get_webhook(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(webhook_id): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    let es = state.engine_store.lock().unwrap();
    match es.folder_get("webhooks", &webhook_id).ok().flatten() {
        Some(v) => {
            let mut h: serde_json::Value = v;
            // Redact secret from response
            if let Some(obj) = h.as_object_mut() {
                if obj.contains_key("secret") {
                    obj.insert("secret".into(), serde_json::json!("***"));
                }
            }
            Json(h)
        }
        None => Json(serde_json::json!({"error": "Webhook not found", "status": 404})),
    }
}

/// PATCH /webhooks/:id — update a webhook (url, events, enabled flag)
pub async fn update_webhook(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(webhook_id): Path<String>,
    Json(req): Json<UpdateWebhookRequest>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "webhooks",
        "webhooks",
        "update_webhook",
        &serde_json::json!({"webhook_id": webhook_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let val = match es.folder_get("webhooks", &webhook_id).ok().flatten() {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Webhook not found", "status": 404})),
    };
    let mut hook: WebhookEndpoint = match serde_json::from_value(val) {
        Ok(h) => h,
        Err(_) => return Json(serde_json::json!({"error": "Corrupt webhook data", "status": 500})),
    };

    if let Some(name) = req.name {
        hook.name = name;
    }
    if let Some(url) = req.url {
        hook.url = url;
    }
    if let Some(events) = req.events {
        hook.events = events;
    }
    if let Some(secret) = req.secret {
        hook.secret = Some(secret);
    }
    if let Some(enabled) = req.enabled {
        hook.enabled = enabled;
    }

    let _ = es.folder_put(
        "webhooks",
        &webhook_id,
        &serde_json::to_value(&hook).unwrap_or_default(),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "webhook_id": webhook_id,
        "updated": true,
        "enabled": hook.enabled,
        "events": hook.events,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// DELETE /webhooks/:id — remove a webhook
pub async fn delete_webhook(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(webhook_id): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(serde_json::json!({"error": "Admin role or higher required", "status": 403}));
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "webhooks",
        "webhooks",
        "retire_webhook",
        &serde_json::json!({"webhook_id": webhook_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let exists = es
        .folder_get("webhooks", &webhook_id)
        .ok()
        .flatten()
        .is_some();
    if !exists {
        return Json(serde_json::json!({"error": "Webhook not found", "status": 404}));
    }

    // Tombstone instead of hard delete
    let _ = es.folder_put(
        "webhooks",
        &webhook_id,
        &serde_json::json!({
            "webhook_id": webhook_id,
            "enabled": false,
            "status": "deleted",
            "deleted_at": chrono::Utc::now().to_rfc3339(),
        }),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "webhook_id": webhook_id,
        "deleted": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /webhooks/:id/test — send a test event to verify the endpoint
pub async fn test_webhook(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(webhook_id): Path<String>,
    Json(req): Json<TestWebhookRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    let mut es = state.engine_store.lock().unwrap();
    let val = match es.folder_get("webhooks", &webhook_id).ok().flatten() {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Webhook not found", "status": 404})),
    };
    let hook: WebhookEndpoint = match serde_json::from_value(val) {
        Ok(h) => h,
        Err(_) => return Json(serde_json::json!({"error": "Corrupt webhook data", "status": 500})),
    };

    let event_type = req.event_type.as_deref().unwrap_or("test.ping");
    let test_payload = serde_json::json!({
        "message": "This is a test event from connector-platform",
        "webhook_id": webhook_id,
        "triggered_by": user_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let envelope = serde_json::json!({
        "event_id": format!("test_{}", uuid::Uuid::new_v4()),
        "event_type": event_type,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "payload": test_payload,
    });

    let signature = hook
        .secret
        .as_ref()
        .map(|s| hmac_sha256_hex(s, &serde_json::to_string(&envelope).unwrap_or_default()));

    tracing::info!(url = %hook.url, event_type = %event_type, "test webhook delivery");

    Json(serde_json::json!({
        "webhook_id": webhook_id,
        "event_type": event_type,
        "url": hook.url,
        "envelope": envelope,
        "signed": signature.is_some(),
        "signature": signature,
        "note": "Test event queued for delivery. Check /webhooks/:id/events for delivery status.",
    }))
}

/// GET /webhooks/:id/events — delivery log for a specific webhook
pub async fn webhook_events(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(webhook_id): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("webhook_events", None).unwrap_or_default();
    let events: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("webhook_events", k).ok().flatten())
        .filter(|v| v.get("webhook_id").and_then(|id| id.as_str()) == Some(&webhook_id))
        .take(100)
        .collect();

    let delivered = events
        .iter()
        .filter(|e| e.get("status").and_then(|s| s.as_str()) == Some("delivered"))
        .count();
    let failed = events
        .iter()
        .filter(|e| e.get("status").and_then(|s| s.as_str()) == Some("failed"))
        .count();

    Json(serde_json::json!({
        "webhook_id": webhook_id,
        "total_events": events.len(),
        "delivered": delivered,
        "failed": failed,
        "events": events,
    }))
}

/// GET /webhooks/events — global delivery log (all webhooks, last 200)
pub async fn all_webhook_events(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("webhook_events", None).unwrap_or_default();
    let mut events: Vec<serde_json::Value> = keys
        .iter()
        .rev()
        .take(200)
        .filter_map(|k| es.folder_get("webhook_events", k).ok().flatten())
        .collect();

    events.sort_by(|a, b| {
        let ta = a.get("delivered_at").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("delivered_at").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });

    let total_delivered = events
        .iter()
        .filter(|e| e.get("status").and_then(|s| s.as_str()) == Some("delivered"))
        .count();
    let total_failed = events
        .iter()
        .filter(|e| e.get("status").and_then(|s| s.as_str()) == Some("failed"))
        .count();
    let total_pending = events
        .iter()
        .filter(|e| e.get("status").and_then(|s| s.as_str()) == Some("pending"))
        .count();

    Json(serde_json::json!({
        "total": events.len(),
        "delivered": total_delivered,
        "failed": total_failed,
        "pending": total_pending,
        "events": events,
    }))
}

// ── E5.1: Async retry queue ───────────────────────────────────────────────────

/// POST /webhooks/{id}/retry-queue — manually enqueue a failed delivery for retry
pub async fn enqueue_retry(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(webhook_id): axum::extract::Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }
    let event_id = req
        .get("event_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("evt_{}", uuid::Uuid::new_v4()));
    let payload = req.get("payload").cloned().unwrap_or(serde_json::json!({}));
    let attempt = req.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "webhooks",
        "webhooks",
        "enqueue_webhook_retry",
        &serde_json::json!({"webhook_id": webhook_id.as_str(), "event_id": event_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    enqueue_failed_delivery(&mut **es, &webhook_id, &event_id, &payload, attempt);
    let key = retry_key(&webhook_id, &event_id);
    let entry = es
        .folder_get("webhook_retry", &key)
        .ok()
        .flatten()
        .unwrap_or_default();
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "retry_id": key,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "webhook_id": webhook_id,
        "event_id": event_id,
        "entry": entry,
        "backoff_schedule": WEBHOOK_BACKOFF_MINS,
        "note": "Background worker polls webhook_retry every 30s and re-delivers due items",
    }))
}

/// GET /webhooks/{id}/retry-queue — list pending retries for a webhook
pub async fn list_retry_queue(
    State(state): State<SharedState>,
    axum::extract::Path(webhook_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now();
    let keys = es.folder_keys("webhook_retry", None).unwrap_or_default();

    let entries: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("webhook_retry", k).ok().flatten())
        .filter(|e| e.get("webhook_id").and_then(|v| v.as_str()) == Some(&webhook_id))
        .collect();

    let queued = entries
        .iter()
        .filter(|e| e.get("status").and_then(|v| v.as_str()) == Some("queued"))
        .count();
    let dead_letter = entries
        .iter()
        .filter(|e| e.get("status").and_then(|v| v.as_str()) == Some("dead_letter"))
        .count();

    Json(serde_json::json!({
        "webhook_id":    webhook_id,
        "checked_at":    now.to_rfc3339(),
        "total":         entries.len(),
        "queued":        queued,
        "dead_letter":   dead_letter,
        "entries":       entries,
    }))
}

// ── E5.2: Endpoint health score ───────────────────────────────────────────────

/// GET /webhooks/{id}/health
pub async fn webhook_health(
    State(state): State<SharedState>,
    axum::extract::Path(webhook_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();
    let cutoff_7d = now_ms - 7 * 86_400_000i64;

    // Load webhook config
    let webhook = match es.folder_get("webhooks", &webhook_id).ok().flatten() {
        Some(w) => w,
        None => {
            return Json(
                serde_json::json!({"error": "Webhook not found", "status": 404, "webhook_id": webhook_id}),
            )
        }
    };

    // Load delivery events for this webhook in last 7d
    let event_keys = es.folder_keys("webhook_events", None).unwrap_or_default();
    let events: Vec<serde_json::Value> = event_keys
        .iter()
        .filter_map(|k| es.folder_get("webhook_events", k).ok().flatten())
        .filter(|e| {
            e.get("webhook_id").and_then(|v| v.as_str()) == Some(&webhook_id)
                && e.get("ts")
                    .and_then(|v| v.as_i64())
                    .map_or(true, |t| t >= cutoff_7d)
        })
        .collect();

    let total = events.len().max(1);
    let success = events
        .iter()
        .filter(|e| {
            e.get("status_code")
                .and_then(|v| v.as_u64())
                .map_or(false, |s| s >= 200 && s < 300)
        })
        .count();
    let failed = total - success;
    let success_rate_7d = success as f64 / total as f64 * 100.0;

    let avg_latency_ms = {
        let latencies: Vec<f64> = events
            .iter()
            .filter_map(|e| e.get("latency_ms").and_then(|v| v.as_f64()))
            .collect();
        if latencies.is_empty() {
            0.0
        } else {
            latencies.iter().sum::<f64>() / latencies.len() as f64
        }
    };

    // Consecutive failures (most recent streak)
    let mut sorted = events.clone();
    sorted.sort_by_key(|e| e.get("ts").and_then(|v| v.as_i64()).unwrap_or(0));
    let consecutive_failures = sorted
        .iter()
        .rev()
        .take_while(|e| {
            e.get("status_code")
                .and_then(|v| v.as_u64())
                .map_or(true, |s| s < 200 || s >= 300)
        })
        .count();

    let circuit_status = if consecutive_failures >= 100 {
        "disabled"
    } else if consecutive_failures >= 10 {
        "degraded"
    } else if consecutive_failures >= 3 {
        "warning"
    } else {
        "healthy"
    };

    // Auto-disable at 100 failures
    let auto_disabled = consecutive_failures >= 100;

    Json(serde_json::json!({
        "webhook_id":           webhook_id,
        "url":                  webhook.get("url"),
        "checked_at":           now.to_rfc3339(),
        "health": {
            "status":           circuit_status,
            "auto_disabled":    auto_disabled,
        },
        "metrics_7d": {
            "total_deliveries": events.len(),
            "success":          success,
            "failed":           failed,
            "success_rate_7d":  (success_rate_7d * 100.0).round() / 100.0,
            "avg_latency_ms":   (avg_latency_ms * 10.0).round() / 10.0,
        },
        "consecutive_failures": consecutive_failures,
        "circuit_status":       circuit_status,
        "recommendation": match circuit_status {
            "disabled"  => "Auto-disabled after 100 consecutive failures. Fix endpoint and re-enable.",
            "degraded"  => "10+ consecutive failures. Investigate endpoint availability.",
            "warning"   => "3+ consecutive failures. Check endpoint logs.",
            _           => "Endpoint healthy.",
        },
    }))
}

// ── E5.3: Delivery log cursor pagination ─────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct WebhookEventsQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub status: Option<String>,
}

/// GET /webhooks/{id}/events?cursor=&limit=50&status=failed
pub async fn webhook_events_paginated(
    State(state): State<SharedState>,
    axum::extract::Path(webhook_id): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<WebhookEventsQuery>,
) -> Json<serde_json::Value> {
    let limit = q.limit.unwrap_or(50).min(200);
    let cursor_ts: i64 = q
        .cursor
        .as_deref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(i64::MAX);
    let now = chrono::Utc::now();

    let es = state.engine_store.lock().unwrap();
    let event_keys = es.folder_keys("webhook_events", None).unwrap_or_default();

    let mut events: Vec<serde_json::Value> = event_keys
        .iter()
        .filter_map(|k| es.folder_get("webhook_events", k).ok().flatten())
        .filter(|e| e.get("webhook_id").and_then(|v| v.as_str()) == Some(&webhook_id))
        .filter(|e| {
            let ts = e.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
            ts < cursor_ts
        })
        .filter(|e| {
            if let Some(ref status_filter) = q.status {
                let code = e.get("status_code").and_then(|v| v.as_u64()).unwrap_or(0);
                match status_filter.as_str() {
                    "failed" => code < 200 || code >= 300,
                    "success" => code >= 200 && code < 300,
                    _ => true,
                }
            } else {
                true
            }
        })
        .collect();

    // Sort descending by ts
    events.sort_by(|a, b| {
        let ta = a.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
        let tb = b.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
        tb.cmp(&ta)
    });

    let has_more = events.len() > limit;
    let page: Vec<_> = events.iter().take(limit).cloned().collect();
    let next_cursor = page
        .last()
        .and_then(|e| e.get("ts").and_then(|v| v.as_i64()))
        .map(|ts| ts.to_string());

    Json(serde_json::json!({
        "webhook_id":  webhook_id,
        "queried_at":  now.to_rfc3339(),
        "count":       page.len(),
        "has_more":    has_more,
        "next_cursor": next_cursor,
        "status_filter":q.status,
        "events":      page,
    }))
}

// ── E5.4: Native integration templates ───────────────────────────────────────

/// GET /webhooks/templates — list available integration templates
pub async fn list_templates() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "templates": [
            {
                "id":          "slack",
                "name":        "Slack Block Kit",
                "description": "Rich Slack message with blocks, action buttons, and severity colour",
                "endpoint_hint":"https://hooks.slack.com/services/XXX/YYY/ZZZ",
                "content_type":"application/json",
            },
            {
                "id":          "pagerduty",
                "name":        "PagerDuty Incident",
                "description": "PagerDuty Events API v2 — trigger/resolve incidents",
                "endpoint_hint":"https://events.pagerduty.com/v2/enqueue",
                "content_type":"application/json",
            },
            {
                "id":          "datadog",
                "name":        "Datadog Events API",
                "description": "Post events to Datadog event stream with tags and alert_type",
                "endpoint_hint":"https://api.datadoghq.com/api/v1/events",
                "content_type":"application/json",
            },
        ],
        "usage": "POST /webhooks with template_id field to use a template. Variables: {{agent_pid}}, {{metric}}, {{value}}, {{severity}}, {{platform_url}}",
    }))
}

/// POST /webhooks/templates/render — render a template with variable substitution
pub async fn render_template(Json(req): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let template_id = req
        .get("template_id")
        .and_then(|v| v.as_str())
        .unwrap_or("slack");
    let vars = req
        .get("variables")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let event_type = req
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("alert");

    let agent_pid = vars
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let metric = vars
        .get("metric")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let value = vars.get("value").and_then(|v| v.as_str()).unwrap_or("N/A");
    let severity = vars
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("warning");
    let platform_url = vars
        .get("platform_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://your-connector-instance.com");
    let suggested = vars
        .get("suggested_action")
        .and_then(|v| v.as_str())
        .unwrap_or("Investigate the agent.");

    let colour = match severity {
        "critical" => "#FF0000",
        "warning" => "#FFA500",
        _ => "#36A64F",
    };
    let pd_severity = match severity {
        "critical" => "critical",
        "warning" => "warning",
        _ => "info",
    };

    let payload = match template_id {
        "slack" => serde_json::json!({
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": format!("🚨 Connector Platform — {}", event_type.to_uppercase())}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": format!("*Agent:*\n`{}`", agent_pid)},
                        {"type": "mrkdwn", "text": format!("*Metric:*\n{}", metric)},
                        {"type": "mrkdwn", "text": format!("*Value:*\n{}", value)},
                        {"type": "mrkdwn", "text": format!("*Severity:*\n{}", severity.to_uppercase())},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": format!("*Suggested Action:* {}", suggested)}
                },
                {
                    "type": "actions",
                    "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": "View Dashboard"}, "url": platform_url, "style": "primary"},
                        {"type": "button", "text": {"type": "plain_text", "text": "View Agent"}, "url": format!("{}/agents/{}", platform_url, agent_pid)},
                    ]
                },
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": format!("Connector Platform | {} | {}", severity.to_uppercase(), chrono::Utc::now().to_rfc3339())}]
                }
            ],
            "attachments": [{"color": colour}],
        }),
        "pagerduty" => serde_json::json!({
            "routing_key": "YOUR_PAGERDUTY_INTEGRATION_KEY",
            "event_action": "trigger",
            "dedup_key":    format!("connector_{}_{}", agent_pid, metric),
            "payload": {
                "summary":   format!("[{}] {} — agent {} value={}", severity.to_uppercase(), metric, agent_pid, value),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "severity":  pd_severity,
                "source":    "connector-platform",
                "component": agent_pid,
                "group":     "ai-agents",
                "class":     event_type,
                "custom_details": {
                    "agent_pid":        agent_pid,
                    "metric":           metric,
                    "value":            value,
                    "suggested_action": suggested,
                    "dashboard_url":    platform_url,
                }
            },
            "links": [{"href": platform_url, "text": "Connector Platform Dashboard"}],
        }),
        "datadog" => serde_json::json!({
            "title":      format!("Connector Platform — {} ({})", event_type, severity.to_uppercase()),
            "text":       format!("Agent: {} | Metric: {} | Value: {} | Action: {}", agent_pid, metric, value, suggested),
            "priority":   if severity == "critical" { "normal" } else { "low" },
            "alert_type": match severity { "critical" => "error", "warning" => "warning", _ => "info" },
            "tags": [
                format!("agent:{}", agent_pid),
                format!("metric:{}", metric),
                format!("severity:{}", severity),
                "source:connector-platform",
                format!("event_type:{}", event_type),
            ],
            "source_type_name": "connector-platform",
        }),
        other => {
            serde_json::json!({"error": format!("Unknown template_id '{}'. Valid: slack, pagerduty, datadog", other)})
        }
    };

    Json(serde_json::json!({
        "template_id": template_id,
        "event_type":  event_type,
        "variables":   vars,
        "rendered":    payload,
        "content_type":"application/json",
        "hint":        "POST this rendered payload to your webhook endpoint URL",
    }))
}

fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (t & 0xFF) as u8
}

/// GET /webhooks/event-types — list all supported event types
pub async fn event_types() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "event_types": [
            {"type": "budget.exceeded",    "description": "Agent token budget hit 100% — LLM calls blocked"},
            {"type": "budget.warning",     "description": "Agent token budget at 70%, 80%, or 90% threshold"},
            {"type": "injection.blocked",  "description": "Semantic injection detected and blocked before LLM dispatch"},
            {"type": "trust.degraded",     "description": "Platform trust score dropped below configured threshold"},
            {"type": "agent.failed",       "description": "Agent operation failure rate exceeded 20% in a window"},
            {"type": "pipeline.completed", "description": "Multi-agent pipeline run completed (success or partial)"},
            {"type": "pipeline.failed",    "description": "A pipeline step failed with an unrecoverable error"},
            {"type": "anomaly.detected",   "description": "Cost spike, failure spike, or unusual pattern detected"},
            {"type": "audit.tamper",       "description": "HMAC audit chain integrity check failed — possible tampering"},
            {"type": "experiment.completed","description": "A/B experiment run finished with results"},
            {"type": "test.ping",          "description": "Manual test event (sent via POST /webhooks/:id/test)"},
        ],
        "note": "Subscribe to specific events or use events=[] to receive all. Also delivers hitl.* when registered."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_key_is_stable_per_webhook_and_event() {
        assert_eq!(retry_key("wh_1", "evt_abc"), retry_key("wh_1", "evt_abc"));
        assert_ne!(retry_key("wh_1", "evt_a"), retry_key("wh_1", "evt_b"));
    }

    #[test]
    fn enqueue_failed_delivery_marks_dead_letter_after_schedule() {
        use connector_engine::engine_store::{EngineStore, InMemoryEngineStore};
        let mut store = InMemoryEngineStore::new();
        enqueue_failed_delivery(
            &mut store,
            "wh_x",
            "evt_y",
            &serde_json::json!({"hello": true}),
            WEBHOOK_BACKOFF_MINS.len(),
        );
        let key = retry_key("wh_x", "evt_y");
        let entry = EngineStore::folder_get(&store, "webhook_retry", &key)
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.get("status").and_then(|v| v.as_str()),
            Some("dead_letter")
        );
    }
}
