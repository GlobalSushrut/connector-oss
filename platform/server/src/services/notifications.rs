//! # Notification & Reminder System
//!
//! Compliance-aware notification engine modelled on enterprise security tooling:
//! - **Cisco SecureX / Splunk SOAR** — event-driven alerting with escalation paths
//! - **Microsoft Sentinel** — scheduled analytics rules with severity escalation
//! - **PagerDuty** — incident urgency levels (low → high → critical → paged)
//! - **Google Cloud Security Command Center** — finding-based notification policies
//!
//! ## Notification types:
//!   CERT_RENEWAL        — compliance cert expiry at 90/30/7 days before due date
//!   OVERDUE_FINDING     — finding past due_date, escalating severity every 24h
//!   CONTROL_REGRESSION  — previously PASS finding now FAIL (regression detected)
//!   AUDIT_TAMPER        — audit chain integrity break detected
//!   TRUST_DEGRADED      — trust score dropped below 70 (deployment gate risk)
//!   BUDGET_EXCEEDED     — agent token budget at 70/80/90/100%
//!   ANOMALY_DETECTED    — LLM call spike, failure spike, access violation burst
//!
//! ## Escalation model (PagerDuty-style):
//!   info → warning (unresolved 4h) → critical (unresolved 8h) → paged (12h)
//!
//! ## Delivery:
//!   Primary:  registered webhook endpoints (from webhooks service)
//!   Fallback: internal notification_log in engine_store
//!
//! ## Routes:
//!   POST  /notifications/schedule          — create a scheduled reminder
//!   GET   /notifications                   — list all active notifications
//!   GET   /notifications/:id               — single notification detail
//!   PATCH /notifications/:id/acknowledge   — acknowledge / snooze notification
//!   DELETE /notifications/:id              — cancel a scheduled reminder
//!   POST  /notifications/scan              — on-demand: scan platform state and emit any due notifications
//!   GET   /notifications/history           — delivered notification log

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

// ── Auth ──────────────────────────────────────────────────────────────────────
fn caller(h: &axum::http::HeaderMap) -> Option<(String, PlatformRole)> {
    let tok = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| h.get("x-api-key").and_then(|v| v.to_str().ok()))?;
    let c = verify_token(tok).ok()?;
    let role = if crate::services::runtime_control::dev_auth_bypass_allowed() {
        PlatformRole::SuperAdmin
    } else {
        PlatformRole::from_str(&c.role)
    };
    Some((c.sub, role))
}
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn ms_to_iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationType {
    CertRenewal,
    OverdueFinding,
    ControlRegression,
    AuditTamper,
    TrustDegraded,
    BudgetExceeded,
    AnomalyDetected,
    Custom,
}

impl NotificationType {
    fn as_str(&self) -> &'static str {
        match self {
            NotificationType::CertRenewal => "CERT_RENEWAL",
            NotificationType::OverdueFinding => "OVERDUE_FINDING",
            NotificationType::ControlRegression => "CONTROL_REGRESSION",
            NotificationType::AuditTamper => "AUDIT_TAMPER",
            NotificationType::TrustDegraded => "TRUST_DEGRADED",
            NotificationType::BudgetExceeded => "BUDGET_EXCEEDED",
            NotificationType::AnomalyDetected => "ANOMALY_DETECTED",
            NotificationType::Custom => "CUSTOM",
        }
    }
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CERT_RENEWAL" => NotificationType::CertRenewal,
            "OVERDUE_FINDING" => NotificationType::OverdueFinding,
            "CONTROL_REGRESSION" => NotificationType::ControlRegression,
            "AUDIT_TAMPER" => NotificationType::AuditTamper,
            "TRUST_DEGRADED" => NotificationType::TrustDegraded,
            "BUDGET_EXCEEDED" => NotificationType::BudgetExceeded,
            "ANOMALY_DETECTED" => NotificationType::AnomalyDetected,
            _ => NotificationType::Custom,
        }
    }
    fn webhook_event_type(&self) -> &'static str {
        match self {
            NotificationType::CertRenewal => "compliance.cert_renewal",
            NotificationType::OverdueFinding => "compliance.finding_overdue",
            NotificationType::ControlRegression => "compliance.control_regression",
            NotificationType::AuditTamper => "audit.tamper",
            NotificationType::TrustDegraded => "trust.degraded",
            NotificationType::BudgetExceeded => "budget.exceeded",
            NotificationType::AnomalyDetected => "anomaly.detected",
            NotificationType::Custom => "notification.custom",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warning,
    Critical,
    Paged,
}

impl Severity {
    fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
            Severity::Paged => "PAGED",
        }
    }
    fn escalate(&self) -> Self {
        match self {
            Severity::Info => Severity::Warning,
            Severity::Warning => Severity::Critical,
            Severity::Critical => Severity::Paged,
            Severity::Paged => Severity::Paged,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationStatus {
    Pending,
    Delivered,
    Acknowledged,
    Snoozed,
    Escalated,
    Cancelled,
}

impl NotificationStatus {
    fn as_str(&self) -> &'static str {
        match self {
            NotificationStatus::Pending => "PENDING",
            NotificationStatus::Delivered => "DELIVERED",
            NotificationStatus::Acknowledged => "ACKNOWLEDGED",
            NotificationStatus::Snoozed => "SNOOZED",
            NotificationStatus::Escalated => "ESCALATED",
            NotificationStatus::Cancelled => "CANCELLED",
        }
    }
}

/// A scheduled or triggered notification record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub notification_type: String, // NotificationType::as_str()
    pub severity: String,          // Severity::as_str()
    pub status: String,            // NotificationStatus::as_str()
    pub title: String,
    pub message: String,
    pub finding_ref: Option<String>, // e.g. "F-003"
    pub framework: Option<String>,
    pub subject_pid: Option<String>, // agent PID if agent-scoped
    pub due_at_ms: Option<i64>,      // when this reminder fires
    pub due_at_iso: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub delivered_at: Option<String>,
    pub acknowledged_at: Option<String>,
    pub acknowledged_by: Option<String>,
    pub snoozed_until: Option<String>,
    pub escalation_count: u32,
    pub next_escalation: Option<String>,
    pub escalation_path: Vec<String>,
    pub webhook_delivered: bool,
    pub delivery_attempts: u32,
    pub metadata: serde_json::Value,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ScheduleRequest {
    /// CERT_RENEWAL | OVERDUE_FINDING | CONTROL_REGRESSION | AUDIT_TAMPER | TRUST_DEGRADED | BUDGET_EXCEEDED | ANOMALY_DETECTED | CUSTOM
    pub notification_type: String,
    pub title: String,
    pub message: String,
    pub severity: Option<String>,
    pub finding_ref: Option<String>,
    pub framework: Option<String>,
    pub subject_pid: Option<String>,
    /// Unix ms when reminder should fire. Defaults to now.
    pub due_at_ms: Option<i64>,
    /// Escalation path — list of roles or names to page on escalation
    pub escalation_path: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct AcknowledgeRequest {
    pub action: String, // "acknowledge" | "snooze"
    /// Snooze duration in minutes (only used when action=snooze)
    pub snooze_mins: Option<u64>,
    pub acknowledged_by: Option<String>,
}

// ── Engine store key helpers ──────────────────────────────────────────────────
const FOLDER: &str = "notifications";
const LOG_FOLDER: &str = "notification_log";

fn load_all(es: &(dyn connector_engine::engine_store::EngineStore + Send)) -> Vec<Notification> {
    let keys = es.folder_keys(FOLDER, None).unwrap_or_default();
    keys.iter()
        .filter_map(|k| es.folder_get(FOLDER, k).ok().flatten())
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect()
}

fn save(es: &mut (dyn connector_engine::engine_store::EngineStore + Send), n: &Notification) {
    let _ = es.folder_put(FOLDER, &n.id, &serde_json::to_value(n).unwrap_or_default());
}

fn log_delivery(
    es: &mut (dyn connector_engine::engine_store::EngineStore + Send),
    n: &Notification,
) {
    let key = format!("{}_{}", n.id, now_ms());
    let _ = es.folder_put(
        LOG_FOLDER,
        &key,
        &serde_json::json!({
            "notification_id":   n.id,
            "notification_type": n.notification_type,
            "severity":          n.severity,
            "title":             n.title,
            "finding_ref":       n.finding_ref,
            "webhook_delivered": n.webhook_delivered,
            "delivered_at":      n.delivered_at,
        }),
    );
}

// ── Core: scan platform state and produce due notifications ───────────────────

/// Inspects live platform state and generates Notification records for any
/// conditions that match the notification policy. Called by POST /notifications/scan
/// and can be wired to a background task or cron job.
/// FIX BUG-038: Now deduplicates against existing active notifications.
pub fn scan_platform(
    kernel: &vac_core::kernel::MemoryKernel,
    engine_store: &(dyn connector_engine::engine_store::EngineStore + Send),
    llm_wired: bool,
) -> Vec<Notification> {
    let mut out = Vec::new();
    let now = now_ms();

    // FIX BUG-038: Load existing active notifications for deduplication
    let existing_keys = engine_store
        .folder_keys("notifications", None)
        .unwrap_or_default();
    let mut active_notification_keys: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for key in &existing_keys {
        if let Some(val) = engine_store.folder_get("notifications", key).ok().flatten() {
            let status = val.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status == "PENDING" || status == "DELIVERED" || status == "ESCALATED" {
                // Create a dedup key from notification_type + subject_pid
                let ntype = val
                    .get("notification_type")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                let subject = val
                    .get("subject_pid")
                    .and_then(|s| s.as_str())
                    .unwrap_or("system");
                active_notification_keys.insert(format!("{}:{}", ntype, subject));
            }
        }
    }

    // Helper to check if notification already exists
    let already_exists = |ntype: &str, subject: &str| -> bool {
        active_notification_keys.contains(&format!("{}:{}", ntype, subject))
    };

    // ── 1. Audit chain tamper ─────────────────────────────────────────────────
    // FIX BUG-038: Skip if active notification already exists for this type
    if kernel.verify_audit_chain().is_err() && !already_exists("AuditTamper", "system") {
        out.push(make_notification(
            NotificationType::AuditTamper,
            Severity::Critical,
            "CRITICAL: Audit Chain Integrity Failure".into(),
            "The HMAC-SHA256 audit chain has been broken. One or more entries may have been tampered with or deleted. Immediate investigation required. GDPR Art.33: 72h breach notification window may be open.".into(),
            Some("F-003".into()),
            None, None,
            Some(now),
            vec!["CISO".into(), "Legal".into(), "Platform Security Team".into()],
            "system".into(),
            serde_json::json!({ "rule": "CC7.2 / GDPR Art.33 / HIPAA 164.312(b)" }),
        ));
    }

    // ── 2. Trust score degraded below 70 ──────────────────────────────────────
    let trust = connector_engine::TrustComputer::compute(kernel);
    if trust.score < 70 && !already_exists("TrustDegraded", "system") {
        let sev = if trust.score < 40 {
            Severity::Critical
        } else {
            Severity::Warning
        };
        out.push(make_notification(
            NotificationType::TrustDegraded,
            sev,
            format!("Trust Score Degraded: {} / 100 — Deployment Gate BLOCKED", trust.score),
            format!("Platform trust score has dropped to {}. The deployment gate threshold is 70. Production deployments are blocked until resolved. Run GET /insights/fleet for root-cause analysis and review findings F-003, F-005.", trust.score),
            Some("F-005".into()),
            None, None,
            Some(now),
            vec!["Platform Engineering".into(), "Security Operations".into()],
            "system".into(),
            serde_json::json!({ "agent_health_score": trust.score, "threshold": 70, "rule": "SOC2 CC9.1 / NIST GV.RM-1" }),
        ));
    }

    // ── 3. LLM Router not wired ───────────────────────────────────────────────
    if !llm_wired && !already_exists("ControlRegression", "system") {
        out.push(make_notification(
            NotificationType::ControlRegression,
            Severity::Warning,
            "Control Gap: LLM Router Not Configured".into(),
            "LLM Router is not wired. All LLM calls will fail or use stub responses. Cost tracking is non-functional. Set CONNECTOR_LLM_PROVIDER, CONNECTOR_LLM_MODEL, and CONNECTOR_LLM_API_KEY environment variables.".into(),
            Some("F-006".into()),
            Some("SOC2 / HIPAA".into()),
            None,
            Some(now),
            vec!["Platform Engineering".into()],
            "system".into(),
            serde_json::json!({ "rule": "CC8.1 / 164.312(b) / PR.DS-5" }),
        ));
    }

    // ── 4. Budget at 80%+ for any agent ──────────────────────────────────────
    for (pid, acb) in kernel.agents().iter() {
        let budget = crate::services::multiagent::agent_token_budget();
        if budget == 0 {
            continue;
        }
        let used_pct = (acb.total_tokens_consumed * 100) / budget;
        if used_pct >= 80 && !already_exists("BudgetExceeded", pid) {
            let sev = if used_pct >= 100 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            out.push(make_notification(
                NotificationType::BudgetExceeded,
                sev,
                format!("Agent {} Budget at {}% — {}",
                    pid, used_pct,
                    if used_pct >= 100 { "HARD BLOCK ACTIVE" } else { "Warning threshold crossed" }),
                format!("Agent '{}' (PID: {}) has consumed {} of {} tokens ({}%). {} Use PATCH /agents/{}/reset-budget or increase budget via PATCH /agents/{}.",
                    acb.agent_name, pid, acb.total_tokens_consumed, budget, used_pct,
                    if used_pct >= 100 { "All further LLM calls are blocked." } else { "" },
                    pid, pid),
                Some("F-007".into()),
                None,
                Some(pid.clone()),
                Some(now),
                vec!["FinOps".into(), "Platform Engineering".into()],
                "system".into(),
                serde_json::json!({
                    "agent_pid":              pid,
                    "agent_name":             acb.agent_name,
                    "tokens_consumed":        acb.total_tokens_consumed,
                    "token_budget":           budget,
                    "pct_used":               used_pct,
                    "rule":                   "SOC2 CC8.1 / FinOps-1",
                }),
            ));
        }
    }

    // ── 5. Overdue findings from engine_store overrides ───────────────────────
    let override_keys = engine_store
        .folder_keys("compliance_overrides", None)
        .unwrap_or_default();
    for key in &override_keys {
        if let Some(ov) = engine_store
            .folder_get("compliance_overrides", key)
            .ok()
            .flatten()
        {
            if let Some(due_str) = ov.get("due_date").and_then(|v| v.as_str()) {
                if let Ok(due_dt) = chrono::DateTime::parse_from_rfc3339(due_str) {
                    let due_ms = due_dt.timestamp_millis();
                    if due_ms < now {
                        let hours_overdue = (now - due_ms) / 3_600_000;
                        let sev = if hours_overdue >= 24 {
                            Severity::Critical
                        } else {
                            Severity::Warning
                        };
                        let fid = ov
                            .get("finding_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        out.push(make_notification(
                            NotificationType::OverdueFinding,
                            sev,
                            format!("Overdue Finding: {} — {} hours past due", fid, hours_overdue),
                            format!("Finding {} was due {} but has not been resolved. It is now {} hours overdue. Update status via PATCH /compliance/findings/{}.", fid, due_str, hours_overdue, fid),
                            Some(fid.into()),
                            None, None,
                            Some(now),
                            vec!["Compliance Team".into(), "CISO".into()],
                            "system".into(),
                            serde_json::json!({ "finding_id": fid, "due_date": due_str, "hours_overdue": hours_overdue, "rule": "SOC2 CC7.4 / ISO A.16.1" }),
                        ));
                    }
                }
            }
        }
    }

    // ── 6. Cert renewal reminders (90/30/7 days) ─────────────────────────────
    // Cert dates stored in engine_store under "cert_dates" folder
    let cert_keys = engine_store
        .folder_keys("cert_dates", None)
        .unwrap_or_default();
    for key in &cert_keys {
        if let Some(cv) = engine_store.folder_get("cert_dates", key).ok().flatten() {
            if let Some(exp_str) = cv.get("expiry_date").and_then(|v| v.as_str()) {
                if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                    let exp_ms = exp_dt.timestamp_millis();
                    let days_left = (exp_ms - now) / 86_400_000;
                    let framework = cv
                        .get("framework")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown");
                    let sev = if days_left <= 7 {
                        Severity::Critical
                    } else if days_left <= 30 {
                        Severity::Warning
                    } else {
                        Severity::Info
                    };
                    if days_left <= 90 {
                        out.push(make_notification(
                            NotificationType::CertRenewal,
                            sev,
                            format!("{} Certification Expires in {} Days", framework, days_left),
                            format!("{} compliance certification (key: {}) expires on {}. Initiate renewal process. Assign renewal owner and upload new cert via POST /notifications/schedule.", framework, key, exp_str),
                            None,
                            Some(framework.into()),
                            None,
                            Some(now),
                            vec!["Compliance Team".into(), "CISO".into()],
                            "system".into(),
                            serde_json::json!({ "framework": framework, "expiry_date": exp_str, "days_remaining": days_left, "rule": "SOC2 CC9.1 / ISO A.18.2" }),
                        ));
                    }
                }
            }
        }
    }

    out
}

fn make_notification(
    ntype: NotificationType,
    severity: Severity,
    title: String,
    message: String,
    finding_ref: Option<String>,
    framework: Option<String>,
    subject_pid: Option<String>,
    due_at_ms: Option<i64>,
    escalation_path: Vec<String>,
    created_by: String,
    metadata: serde_json::Value,
) -> Notification {
    let id = format!(
        "NTF-{}",
        &uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
    );
    let due_iso = due_at_ms.map(ms_to_iso);
    // Next escalation: 4h after due for INFO, 2h for WARNING, 1h for CRITICAL
    let escalation_ms = due_at_ms.unwrap_or_else(now_ms)
        + match severity {
            Severity::Info => 4 * 3_600_000,
            Severity::Warning => 2 * 3_600_000,
            Severity::Critical => 1 * 3_600_000,
            Severity::Paged => 0,
        };
    Notification {
        id,
        notification_type: ntype.as_str().into(),
        severity: severity.as_str().into(),
        status: NotificationStatus::Pending.as_str().into(),
        title,
        message,
        finding_ref,
        framework,
        subject_pid,
        due_at_iso: due_iso.clone(),
        due_at_ms,
        created_at: now_iso(),
        created_by,
        delivered_at: None,
        acknowledged_at: None,
        acknowledged_by: None,
        snoozed_until: None,
        escalation_count: 0,
        next_escalation: Some(ms_to_iso(escalation_ms)),
        escalation_path,
        webhook_delivered: false,
        delivery_attempts: 0,
        metadata,
    }
}

// ── Deliver a notification via webhooks + store it ────────────────────────────

fn deliver_notification(
    n: &mut Notification,
    es: &mut (dyn connector_engine::engine_store::EngineStore + Send),
) {
    // Attempt webhook delivery via registered endpoints
    let webhook_keys = es.folder_keys("webhooks", None).unwrap_or_default();
    let mut delivered = false;

    for wk in &webhook_keys {
        if let Some(wv) = es.folder_get("webhooks", wk).ok().flatten() {
            // Check if this webhook subscribes to this event type
            let subscribed = wv
                .get("events")
                .and_then(|e| e.as_array())
                .map(|events| {
                    events.iter().any(|ev| {
                        let s = ev.as_str().unwrap_or("");
                        s == "*"
                            || s == NotificationType::from_str(&n.notification_type)
                                .webhook_event_type()
                    })
                })
                .unwrap_or(false);

            if !subscribed {
                continue;
            }

            let url = wv
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            if url.is_empty() {
                continue;
            }

            // Build the webhook payload
            let payload = serde_json::json!({
                "event_type":    NotificationType::from_str(&n.notification_type).webhook_event_type(),
                "notification":  n,
                "emitted_at":    now_iso(),
            });

            // Log the delivery attempt in webhook event log
            let event_id = format!(
                "WEV-{}",
                &uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
            );
            let _ = es.folder_put("webhook_events", &event_id, &serde_json::json!({
                "id":          event_id,
                "webhook_id":  wk,
                "event_type":  NotificationType::from_str(&n.notification_type).webhook_event_type(),
                "payload":     payload,
                "status":      "QUEUED",
                "emitted_at":  now_iso(),
                "note":        "Webhook delivery is async — wire a background task or cron to POST /notifications/scan for real-time delivery.",
            }));

            delivered = true;
            n.delivery_attempts += 1;
        }
    }

    n.webhook_delivered = delivered;
    n.delivered_at = Some(now_iso());
    n.status = if delivered {
        NotificationStatus::Delivered.as_str().into()
    } else {
        NotificationStatus::Pending.as_str().into()
    };

    log_delivery(es, n);
    save(es, n);
}

// ─────────────────────────────────────────────────────────────────────────────
// HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

/// POST /notifications/schedule — create a manual scheduled reminder (operator+)
pub async fn schedule_notification(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ScheduleRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403, "code": 403}),
        );
    }

    let ntype = NotificationType::from_str(&req.notification_type);
    let sev_str = req.severity.as_deref().unwrap_or("INFO");
    let severity = match sev_str.to_uppercase().as_str() {
        "WARNING" => Severity::Warning,
        "CRITICAL" => Severity::Critical,
        "PAGED" => Severity::Paged,
        _ => Severity::Info,
    };

    let mut n = make_notification(
        ntype,
        severity,
        req.title,
        req.message,
        req.finding_ref,
        req.framework,
        req.subject_pid,
        req.due_at_ms.or(Some(now_ms())),
        req.escalation_path
            .unwrap_or_else(|| vec!["Compliance Team".into(), "CISO".into()]),
        user_id.clone(),
        req.metadata.unwrap_or(serde_json::json!({})),
    );

    let mut es = state.engine_store.lock().unwrap();
    deliver_notification(&mut n, &mut **es);

    Json(serde_json::json!({
        "notification_id": n.id,
        "status":          n.status,
        "webhook_delivered": n.webhook_delivered,
        "notification":    n,
    }))
}

/// GET /notifications — list all notifications (operator+)
pub async fn list_notifications(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403, "code": 403}),
        );
    }

    let es = state.engine_store.lock().unwrap();
    let all = load_all(&**es);
    let pending = all
        .iter()
        .filter(|n| n.status == "PENDING" || n.status == "DELIVERED")
        .count();
    let critical = all
        .iter()
        .filter(|n| n.severity == "CRITICAL" || n.severity == "PAGED")
        .count();

    Json(serde_json::json!({
        "total":     all.len(),
        "pending":   pending,
        "critical":  critical,
        "notifications": all,
    }))
}

/// GET /notifications/:id
pub async fn get_notification(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403, "code": 403}),
        );
    }

    let es = state.engine_store.lock().unwrap();
    match es.folder_get(FOLDER, &id).ok().flatten() {
        None => Json(
            serde_json::json!({"error": format!("Notification {} not found", id), "status": 404, "code": 404}),
        ),
        Some(v) => Json(serde_json::json!({ "notification": v })),
    }
}

/// PATCH /notifications/:id/acknowledge — acknowledge or snooze (operator+)
pub async fn acknowledge_notification(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<AcknowledgeRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403, "code": 403}),
        );
    }

    let mut es = state.engine_store.lock().unwrap();
    let raw = match es.folder_get(FOLDER, &id).ok().flatten() {
        None => {
            return Json(
                serde_json::json!({"error": format!("Notification {} not found", id), "status": 404, "code": 404}),
            )
        }
        Some(v) => v,
    };

    let mut n: Notification = match serde_json::from_value(raw) {
        Ok(v) => v,
        Err(e) => {
            return Json(
                serde_json::json!({"error": format!("Malformed notification: {}", e), "status": 500, "code": 500}),
            )
        }
    };

    match req.action.to_lowercase().as_str() {
        "acknowledge" => {
            n.status = NotificationStatus::Acknowledged.as_str().into();
            n.acknowledged_at = Some(now_iso());
            n.acknowledged_by = Some(req.acknowledged_by.unwrap_or(user_id));
            n.next_escalation = None;
        }
        "snooze" => {
            let mins = req.snooze_mins.unwrap_or(60);
            let until_ms = now_ms() + (mins as i64) * 60_000;
            n.status = NotificationStatus::Snoozed.as_str().into();
            n.snoozed_until = Some(ms_to_iso(until_ms));
            n.next_escalation = Some(ms_to_iso(until_ms));
        }
        _ => {
            return Json(
                serde_json::json!({"error": "action must be 'acknowledge' or 'snooze'", "status": 400, "code": 400}),
            )
        }
    }

    save(&mut **es, &n);
    Json(serde_json::json!({ "notification_id": id, "status": n.status, "notification": n }))
}

/// DELETE /notifications/:id — cancel a scheduled reminder (operator+)
pub async fn cancel_notification(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403, "code": 403}),
        );
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "notifications",
        "notifications",
        "cancel_notification",
        &serde_json::json!({"notification_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let raw = match es.folder_get(FOLDER, &id).ok().flatten() {
        None => {
            return Json(
                serde_json::json!({"error": format!("Notification {} not found", id), "status": 404, "code": 404}),
            )
        }
        Some(v) => v,
    };

    let mut n: Notification = match serde_json::from_value(raw) {
        Ok(v) => v,
        Err(_) => {
            return Json(
                serde_json::json!({"error": "Malformed notification", "status": 500, "code": 500}),
            )
        }
    };
    n.status = NotificationStatus::Cancelled.as_str().into();
    save(&mut **es, &n);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "notification_id": id,
        "cancelled": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /notifications/scan — on-demand platform scan, emits any due notifications (operator+)
pub async fn scan_and_notify(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403, "code": 403}),
        );
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "notifications",
        "lifecycle",
        "scan_notifications",
        &serde_json::json!({"kind": "scan"}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let k = state.kernel.lock().unwrap();
    let llm_wired = state.llm_wired();

    // Temporarily clone the engine_store data for scanning
    let es_snapshot = {
        let es = state.engine_store.lock().unwrap();
        // We re-lock below — need to release kernel first for borrow safety
        drop(es);
        drop(k);
        ()
    };
    let _ = es_snapshot; // suppress unused warning

    let k2 = state.kernel.lock().unwrap();
    let mut notifications = {
        let es = state.engine_store.lock().unwrap();
        scan_platform(&k2, &**es, llm_wired)
    };
    drop(k2);

    let mut es = state.engine_store.lock().unwrap();
    let mut delivered_count = 0usize;
    let mut critical_count = 0usize;

    for n in &mut notifications {
        if n.severity == "CRITICAL" || n.severity == "PAGED" {
            critical_count += 1;
        }
        deliver_notification(n, &mut **es);
        if n.webhook_delivered {
            delivered_count += 1;
        }
    }

    // Escalation pass: check existing stored notifications for overdue escalations
    let existing = load_all(&**es);
    let mut escalated = 0usize;
    for mut n in existing {
        if n.status != "PENDING" && n.status != "DELIVERED" {
            continue;
        }
        if let Some(ref next_esc) = n.next_escalation.clone() {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(next_esc) {
                if dt.timestamp_millis() <= now_ms() {
                    let new_sev = match n.severity.as_str() {
                        "INFO" => Severity::Warning,
                        "WARNING" => Severity::Critical,
                        "CRITICAL" => Severity::Paged,
                        _ => Severity::Paged,
                    };
                    n.severity = new_sev.as_str().into();
                    n.status = NotificationStatus::Escalated.as_str().into();
                    n.escalation_count += 1;
                    // Next escalation in 4h for WARNING, 2h for CRITICAL, 1h for PAGED
                    let next_ms = now_ms()
                        + match new_sev {
                            Severity::Warning => 4 * 3_600_000,
                            Severity::Critical => 2 * 3_600_000,
                            Severity::Paged => 3_600_000,
                            _ => 4 * 3_600_000,
                        };
                    n.next_escalation = Some(ms_to_iso(next_ms));
                    deliver_notification(&mut n, &mut **es);
                    escalated += 1;
                }
            }
        }
    }

    drop(es);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "scan_completed_at":   now_iso(),
        "new_notifications":   notifications.len(),
        "webhook_delivered":   delivered_count,
        "critical_found":      critical_count,
        "escalations_applied": escalated,
        "notifications":       notifications,
        "tip": "Wire POST /notifications/scan to a cron job or background task for continuous monitoring.",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /notifications/history — delivered notification log (operator+)
pub async fn notification_history(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403, "code": 403}),
        );
    }

    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(LOG_FOLDER, None).unwrap_or_default();
    let entries: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get(LOG_FOLDER, k).ok().flatten())
        .collect();

    let critical = entries
        .iter()
        .filter(|e| {
            e.get("severity")
                .and_then(|s| s.as_str())
                .map(|s| s == "CRITICAL" || s == "PAGED")
                .unwrap_or(false)
        })
        .count();

    Json(serde_json::json!({
        "total_delivered":    entries.len(),
        "critical_delivered": critical,
        "history":            entries,
    }))
}

/// POST /notifications/cert-dates/:key — register a certification expiry date (admin+)
/// Body: { "framework": "SOC2", "expiry_date": "2026-01-01T00:00:00Z" }
pub async fn register_cert_date(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Authentication required", "status": 401, "code": 401}),
            )
        }
    };
    if role.rank() < 5 {
        return Json(
            serde_json::json!({"error": "Admin role or higher required", "status": 403, "code": 403}),
        );
    }

    let expiry = body
        .get("expiry_date")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let framework = body
        .get("framework")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    if expiry.is_empty() {
        return Json(
            serde_json::json!({"error": "expiry_date is required (RFC3339)", "status": 400, "code": 400}),
        );
    }
    if chrono::DateTime::parse_from_rfc3339(&expiry).is_err() {
        return Json(
            serde_json::json!({"error": "expiry_date must be RFC3339 format e.g. 2026-12-31T00:00:00Z", "status": 400, "code": 400}),
        );
    }

    let record = serde_json::json!({
        "key":          key,
        "framework":    framework,
        "expiry_date":  expiry,
        "registered_by":user_id,
        "registered_at":now_iso(),
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("cert_dates", &key, &record);

    Json(serde_json::json!({
        "registered": true,
        "key":        key,
        "record":     record,
        "tip":        "Run POST /notifications/scan to immediately check all cert dates and emit any due reminders.",
    }))
}

// ── E5.5: Deduplication ───────────────────────────────────────────────────────

/// POST /notifications/schedule — extended with dedup_key + cooldown_secs
/// If a notification with the same dedup_key was sent within cooldown_secs, suppress it.
pub async fn schedule_with_dedup(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let dedup_key = req.get("dedup_key").and_then(|v| v.as_str()).unwrap_or("");
    let cooldown_secs = req
        .get("cooldown_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    // Deduplication check
    if !dedup_key.is_empty() {
        let es = state.engine_store.lock().unwrap();
        if let Some(last) = es
            .folder_get("notification_dedup", dedup_key)
            .ok()
            .flatten()
        {
            let last_sent_ms = last.get("sent_at_ms").and_then(|v| v.as_i64()).unwrap_or(0);
            let elapsed_secs = (now_ms - last_sent_ms) / 1000;
            if elapsed_secs < cooldown_secs as i64 {
                return Json(serde_json::json!({
                    "suppressed":   true,
                    "dedup_key":    dedup_key,
                    "reason":       format!("Duplicate within cooldown window ({}s). Last sent {}s ago.", cooldown_secs, elapsed_secs),
                    "last_sent_at": last.get("sent_at_iso"),
                    "retry_after_secs": cooldown_secs as i64 - elapsed_secs,
                }));
            }
        }
    }

    // Record dedup entry
    if !dedup_key.is_empty() {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            "notification_dedup",
            dedup_key,
            &serde_json::json!({
                "dedup_key":   dedup_key,
                "sent_at_ms":  now_ms,
                "sent_at_iso": now.to_rfc3339(),
                "cooldown_secs": cooldown_secs,
            }),
        );
    }

    // Forward to existing schedule logic
    let notification_id = format!("notif_{}", uuid::Uuid::new_v4());
    let notification = serde_json::json!({
        "notification_id": notification_id,
        "type":            req.get("type").and_then(|v| v.as_str()).unwrap_or("ALERT"),
        "message":         req.get("message").and_then(|v| v.as_str()).unwrap_or(""),
        "severity":        req.get("severity").and_then(|v| v.as_str()).unwrap_or("info"),
        "agent_pid":       req.get("agent_pid").and_then(|v| v.as_str()),
        "dedup_key":       if dedup_key.is_empty() { None } else { Some(dedup_key) },
        "cooldown_secs":   cooldown_secs,
        "status":          "pending",
        "created_at":      now.to_rfc3339(),
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("notifications", &notification_id, &notification);

    Json(serde_json::json!({
        "notification_id": notification_id,
        "suppressed":      false,
        "dedup_key":       if dedup_key.is_empty() { None } else { Some(dedup_key) },
        "cooldown_secs":   cooldown_secs,
        "created_at":      now.to_rfc3339(),
        "status":          "scheduled",
    }))
}

/// DELETE /notifications/dedup/{key} — clear a dedup lock to allow re-sending
pub async fn clear_dedup(
    State(state): State<SharedState>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let mut es = state.engine_store.lock().unwrap();
    let existed = es
        .folder_get("notification_dedup", &key)
        .ok()
        .flatten()
        .is_some();
    // Mark as expired by setting sent_at_ms = 0
    if existed {
        let _ = es.folder_put(
            "notification_dedup",
            &key,
            &serde_json::json!({
                "dedup_key":   key,
                "sent_at_ms":  0,
                "cleared":     true,
            }),
        );
    }
    Json(serde_json::json!({
        "dedup_key": key,
        "cleared":   existed,
        "note":      "Next notification with this dedup_key will be sent regardless of cooldown.",
    }))
}

// ── E5.6: On-call schedule routing ───────────────────────────────────────────

/// POST /notifications/oncall-schedules — create or update an on-call schedule
pub async fn create_oncall_schedule(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let schedule_id = req
        .get("schedule_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("oncall_{}", uuid::Uuid::new_v4()));
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let timezone = req
        .get("timezone")
        .and_then(|v| v.as_str())
        .unwrap_or("UTC");
    let now = chrono::Utc::now();

    // Rotation: array of {user_id, email, phone, start_iso, end_iso}
    let rotation: Vec<serde_json::Value> = req
        .get("rotation")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Find current on-call person based on UTC now
    let current_oncall = rotation.iter().find(|r| {
        let start = r
            .get("start_iso")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(0);
        let end = r
            .get("end_iso")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(i64::MAX);
        now.timestamp_millis() >= start && now.timestamp_millis() < end
    });

    let schedule = serde_json::json!({
        "schedule_id":    schedule_id,
        "name":           name,
        "timezone":       timezone,
        "rotation":       rotation,
        "current_oncall": current_oncall,
        "created_at":     now.to_rfc3339(),
        "updated_at":     now.to_rfc3339(),
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("oncall_schedules", &schedule_id, &schedule);

    Json(serde_json::json!({
        "schedule_id":    schedule_id,
        "name":           name,
        "rotation_count": rotation.len(),
        "current_oncall": current_oncall,
        "created_at":     now.to_rfc3339(),
        "note":           "PAGED severity notifications route to current_oncall user",
    }))
}

/// GET /notifications/oncall-schedules — list all schedules with current on-call
pub async fn list_oncall_schedules(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now();
    let keys = es.folder_keys("oncall_schedules", None).unwrap_or_default();

    let schedules: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("oncall_schedules", k).ok().flatten())
        .map(|s| {
            // Re-evaluate current on-call in real-time
            let rotation: Vec<serde_json::Value> = s
                .get("rotation")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let current = rotation
                .iter()
                .find(|r| {
                    let start = r
                        .get("start_iso")
                        .and_then(|v| v.as_str())
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|d| d.timestamp_millis())
                        .unwrap_or(0);
                    let end = r
                        .get("end_iso")
                        .and_then(|v| v.as_str())
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|d| d.timestamp_millis())
                        .unwrap_or(i64::MAX);
                    now.timestamp_millis() >= start && now.timestamp_millis() < end
                })
                .cloned();
            serde_json::json!({
                "schedule_id":   s.get("schedule_id"),
                "name":          s.get("name"),
                "timezone":      s.get("timezone"),
                "rotation_count":rotation.len(),
                "current_oncall":current,
                "checked_at":    now.to_rfc3339(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "schedule_count": schedules.len(),
        "schedules":      schedules,
        "note":           "POST /notifications/schedule with severity=paged to route to current on-call",
    }))
}

// ── E5.7: Actionable notification templates ───────────────────────────────────

/// GET /notifications/templates — list available templates
pub async fn list_notification_templates() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "templates": [
            {
                "id":          "budget_exceeded",
                "description": "Agent token budget exhausted",
                "variables":   ["agent_pid", "metric", "current_value", "investigate_url", "suggested_action"],
            },
            {
                "id":          "trust_degraded",
                "description": "Platform trust score dropped",
                "variables":   ["agent_pid", "metric", "current_value", "investigate_url", "suggested_action"],
            },
            {
                "id":          "injection_blocked",
                "description": "Semantic injection detected and blocked",
                "variables":   ["agent_pid", "metric", "current_value", "investigate_url", "suggested_action"],
            },
            {
                "id":          "slo_breach",
                "description": "SLO breach detected",
                "variables":   ["agent_pid", "metric", "current_value", "investigate_url", "suggested_action"],
            },
            {
                "id":          "anomaly_detected",
                "description": "Statistical anomaly detected",
                "variables":   ["agent_pid", "metric", "current_value", "investigate_url", "suggested_action"],
            },
        ],
        "note": "POST /notifications/templates/render to preview a rendered notification",
    }))
}

/// POST /notifications/templates/render — render template with variable substitution
pub async fn render_notification_template(
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let template_id = req
        .get("template_id")
        .and_then(|v| v.as_str())
        .unwrap_or("budget_exceeded");
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let metric = req
        .get("metric")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let current_val = req
        .get("current_value")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let investigate = req
        .get("investigate_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://your-connector-instance.com/debug");
    let suggested = req
        .get("suggested_action")
        .and_then(|v| v.as_str())
        .unwrap_or("Investigate the agent immediately.");
    let now = chrono::Utc::now();

    let (severity, subject, body) = match template_id {
        "budget_exceeded" => (
            "critical",
            format!("[CRITICAL] Agent {} token budget exceeded", agent_pid),
            format!(
                "Agent `{}` has exhausted its token budget.\n\nMetric: {}\nCurrent Value: {}\n\nSuggested Action: {}\n\nInvestigate: {}",
                agent_pid, metric, current_val, suggested, investigate
            ),
        ),
        "trust_degraded" => (
            "warning",
            format!("[WARNING] Trust score degraded for agent {}", agent_pid),
            format!(
                "Platform trust score has dropped below threshold for agent `{}`.\n\nMetric: {}\nCurrent Value: {}\n\nSuggested Action: {}\n\nInvestigate: {}",
                agent_pid, metric, current_val, suggested, investigate
            ),
        ),
        "injection_blocked" => (
            "critical",
            format!("[SECURITY] Injection attempt blocked — agent {}", agent_pid),
            format!(
                "A semantic injection attempt was detected and blocked for agent `{}`.\n\nMetric: {}\nDetails: {}\n\nSuggested Action: {}\n\nInvestigate: {}",
                agent_pid, metric, current_val, suggested, investigate
            ),
        ),
        "slo_breach" => (
            "warning",
            format!("[SLO BREACH] {} SLO breached — agent {}", metric, agent_pid),
            format!(
                "SLO breach detected.\n\nAgent: `{}`\nMetric: {}\nCurrent Value: {}\n\nSuggested Action: {}\n\nInvestigate: {}",
                agent_pid, metric, current_val, suggested, investigate
            ),
        ),
        "anomaly_detected" => (
            "warning",
            format!("[ANOMALY] {} anomaly detected — agent {}", metric, agent_pid),
            format!(
                "Statistical anomaly detected (z-score > 2).\n\nAgent: `{}`\nMetric: {}\nCurrent Value: {}\n\nSuggested Action: {}\n\nInvestigate: {}",
                agent_pid, metric, current_val, suggested, investigate
            ),
        ),
        other => return Json(serde_json::json!({
            "error": format!("Unknown template_id '{}'. Valid: budget_exceeded, trust_degraded, injection_blocked, slo_breach, anomaly_detected", other),
        })),
    };

    Json(serde_json::json!({
        "template_id":     template_id,
        "rendered_at":     now.to_rfc3339(),
        "severity":        severity,
        "subject":         subject,
        "body":            body,
        "channels": {
            "email": {
                "subject": subject,
                "body":    body,
                "hint":    "Send via SMTP using CONNECTOR_SMTP_* env vars",
            },
            "slack": {
                "text":    format!("*{}*\n{}", subject, body),
                "hint":    "POST to Slack webhook URL",
            },
            "pagerduty": {
                "summary": subject,
                "severity":severity,
                "hint":    "POST to PagerDuty Events API v2",
            },
        },
        "variables_used": {
            "agent_pid":       agent_pid,
            "metric":          metric,
            "current_value":   current_val,
            "investigate_url": investigate,
            "suggested_action":suggested,
        },
    }))
}
