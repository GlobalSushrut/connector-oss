//! Alert dispatch — Slack, PagerDuty, OpsGenie, generic webhook.
//!
//! Called by:
//!   - budgets::enforcement_sweep  → on breach and warn
//!   - forecast::run_anomaly_detection → on new anomaly
//!   - routes::test_alert          → on-demand test
//!
//! Reads ll_notification_channels + ll_notification_rules to decide
//! which channels fire for which event types.
//! All failures are logged but never propagate — alerts must not crash the caller.

use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct AlertPayload {
    pub event_type:    String,   // budget_breach | budget_warn | anomaly | test
    pub severity:      String,   // critical | high | medium | info
    pub title:         String,
    pub body:          String,
    pub detail:        Value,
}

pub struct AlertDispatcher {
    http: Client,
}

impl AlertDispatcher {
    pub fn new() -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("ledgerlens-alerts/0.1")
                .build()
                .unwrap(),
        }
    }

    /// Dispatch to all enabled channels that match this event_type.
    pub async fn dispatch(&self, pool: &PgPool, payload: &AlertPayload) {
        let channels = match self.load_channels(pool, &payload.event_type).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to load alert channels: {e}");
                return;
            }
        };

        for ch in channels {
            let result = match ch.channel_type.as_str() {
                "slack"      => self.send_slack(&ch.config, payload).await,
                "pagerduty"  => self.send_pagerduty(&ch.config, payload).await,
                "opsgenie"   => self.send_opsgenie(&ch.config, payload).await,
                "webhook"    => self.send_webhook(&ch.config, payload).await,
                "email"      => { tracing::info!(channel=%ch.name, "Email alert skipped (SMTP not configured)"); Ok(()) }
                other        => { tracing::warn!(channel_type=%other, "Unknown channel type"); Ok(()) }
            };
            match result {
                Ok(()) => {
                    tracing::info!(channel = %ch.name, event = %payload.event_type, "Alert dispatched");
                    metrics::counter!("ledgerlens_alerts_dispatched_total",
                        "channel_type" => ch.channel_type.clone(),
                        "event"        => payload.event_type.clone(),
                    ).increment(1);
                }
                Err(e) => {
                    tracing::error!(channel = %ch.name, err = %e, "Alert dispatch failed");
                    metrics::counter!("ledgerlens_alert_failures_total",
                        "channel_type" => ch.channel_type.clone(),
                    ).increment(1);
                }
            }
        }
    }

    // ── Slack ─────────────────────────────────────────────────────────────────

    async fn send_slack(&self, config: &Value, p: &AlertPayload) -> Result<()> {
        let url = config["webhook_url"].as_str()
            .ok_or_else(|| anyhow::anyhow!("slack: missing webhook_url"))?;

        let color = match p.severity.as_str() {
            "critical" => "#FF0000",
            "high"     => "#FF8C00",
            "medium"   => "#FFD700",
            _          => "#36a64f",
        };

        let body = json!({
            "text": format!("*LedgerLens* — {}", p.title),
            "attachments": [{
                "color":    color,
                "title":    p.title,
                "text":     p.body,
                "fields": [
                    { "title": "Severity", "value": p.severity, "short": true },
                    { "title": "Event",    "value": p.event_type, "short": true },
                ],
                "footer":   "LedgerLens AI FinOps",
                "ts":       chrono::Utc::now().timestamp(),
            }]
        });

        let resp = self.http.post(url).json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Slack returned {}", resp.status());
        }
        Ok(())
    }

    // ── PagerDuty ─────────────────────────────────────────────────────────────

    async fn send_pagerduty(&self, config: &Value, p: &AlertPayload) -> Result<()> {
        let key = config["routing_key"].as_str()
            .ok_or_else(|| anyhow::anyhow!("pagerduty: missing routing_key"))?;

        let severity = match p.severity.as_str() {
            "critical" => "critical",
            "high"     => "error",
            "medium"   => "warning",
            _          => "info",
        };

        let body = json!({
            "routing_key":  key,
            "event_action": "trigger",
            "payload": {
                "summary":   p.title,
                "severity":  severity,
                "source":    "ledgerlens",
                "custom_details": {
                    "body":   p.body,
                    "detail": p.detail,
                }
            }
        });

        let resp = self.http
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("PagerDuty returned {}", resp.status());
        }
        Ok(())
    }

    // ── OpsGenie ──────────────────────────────────────────────────────────────

    async fn send_opsgenie(&self, config: &Value, p: &AlertPayload) -> Result<()> {
        let api_key = config["api_key"].as_str()
            .ok_or_else(|| anyhow::anyhow!("opsgenie: missing api_key"))?;

        let priority = match p.severity.as_str() {
            "critical" => "P1",
            "high"     => "P2",
            "medium"   => "P3",
            _          => "P4",
        };

        let body = json!({
            "message":   p.title,
            "description": p.body,
            "priority":  priority,
            "source":    "ledgerlens",
            "tags":      ["ai-finops", &p.event_type],
            "details":   { "detail": p.detail.to_string() },
        });

        let resp = self.http
            .post("https://api.opsgenie.com/v2/alerts")
            .header("Authorization", format!("GenieKey {api_key}"))
            .json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("OpsGenie returned {}", resp.status());
        }
        Ok(())
    }

    // ── Generic webhook ───────────────────────────────────────────────────────

    async fn send_webhook(&self, config: &Value, p: &AlertPayload) -> Result<()> {
        let url = config["url"].as_str()
            .ok_or_else(|| anyhow::anyhow!("webhook: missing url"))?;

        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(secret) = config["secret"].as_str() {
            headers.insert(
                "X-LedgerLens-Signature",
                format!("sha256={}", hmac_sign(secret, &p.body)).parse()?,
            );
        }

        let body = json!({
            "event_type": p.event_type,
            "severity":   p.severity,
            "title":      p.title,
            "body":       p.body,
            "detail":     p.detail,
            "timestamp":  chrono::Utc::now(),
        });

        let resp = self.http
            .post(url)
            .headers(headers)
            .json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Webhook returned {}", resp.status());
        }
        Ok(())
    }

    // ── DB helpers ────────────────────────────────────────────────────────────

    async fn load_channels(&self, pool: &PgPool, event_type: &str) -> Result<Vec<ChannelRow>> {
        let rows = sqlx::query(
            "SELECT c.id, c.name, c.channel_type, c.config
             FROM ll_notification_channels c
             JOIN ll_notification_rules r ON r.channel_id = c.id
             WHERE c.enabled = TRUE
               AND r.enabled = TRUE
               AND (r.event_type = $1 OR r.event_type = 'all')"
        ).bind(event_type).fetch_all(pool).await?;

        Ok(rows.iter().map(|r| ChannelRow {
            name:         r.try_get("name").unwrap_or_default(),
            channel_type: r.try_get("channel_type").unwrap_or_default(),
            config:       r.try_get("config").unwrap_or(json!({})),
        }).collect())
    }
}

struct ChannelRow {
    name:         String,
    channel_type: String,
    config:       Value,
}

fn hmac_sign(secret: &str, data: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
