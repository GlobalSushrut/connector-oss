use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct WebhookEngine {
    db: PgPool,
    endpoints: Vec<String>,
    bearer: Option<String>,
}

impl WebhookEngine {
    pub fn new(db: PgPool, endpoints: Vec<String>, bearer: Option<String>) -> Self {
        Self {
            db,
            endpoints,
            bearer: bearer.filter(|v| !v.trim().is_empty()),
        }
    }

    pub fn start_worker(&self) {
        let db = self.db.clone();
        let bearer = self.bearer.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let tick = std::time::Duration::from_secs(5);
            loop {
                let rows = sqlx::query(
                    "SELECT id, endpoint, event_type, payload, attempts \
                     FROM witness_webhook_queue \
                     WHERE status IN ('pending','retry') AND next_attempt_at <= NOW() \
                     ORDER BY created_at ASC LIMIT 25"
                )
                .fetch_all(&db)
                .await
                .unwrap_or_default();

                for row in rows {
                    let id: Uuid = row.get("id");
                    let endpoint: String = row.get("endpoint");
                    let event_type: String = row.get("event_type");
                    let payload: serde_json::Value = row.get("payload");
                    let attempts: i32 = row.get("attempts");

                    let mut req = client
                        .post(&endpoint)
                        .json(&serde_json::json!({
                            "event_type": event_type,
                            "payload": payload,
                        }));
                    if let Some(token) = bearer.as_ref() {
                        req = req.bearer_auth(token);
                    }
                    let result = req.send().await;
                    match result {
                        Ok(resp) if resp.status().is_success() => {
                            let _ = sqlx::query(
                                "UPDATE witness_webhook_queue \
                                 SET status = 'delivered', delivered_at = NOW(), updated_at = NOW() \
                                 WHERE id = $1"
                            )
                            .bind(id)
                            .execute(&db)
                            .await;
                        }
                        Ok(resp) => {
                            let next_attempts = attempts + 1;
                            let dead = next_attempts >= 5;
                            let status = if dead { "dead" } else { "retry" };
                            let backoff_secs = 2_i64.pow(next_attempts.min(6) as u32);
                            let _ = sqlx::query(
                                "UPDATE witness_webhook_queue \
                                 SET status = $1, attempts = $2, last_error = $3, \
                                     next_attempt_at = NOW() + ($4::text || ' seconds')::interval, updated_at = NOW() \
                                 WHERE id = $5"
                            )
                            .bind(status)
                            .bind(next_attempts)
                            .bind(format!("HTTP {}", resp.status()))
                            .bind(backoff_secs.to_string())
                            .bind(id)
                            .execute(&db)
                            .await;
                        }
                        Err(e) => {
                            let next_attempts = attempts + 1;
                            let dead = next_attempts >= 5;
                            let status = if dead { "dead" } else { "retry" };
                            let backoff_secs = 2_i64.pow(next_attempts.min(6) as u32);
                            let _ = sqlx::query(
                                "UPDATE witness_webhook_queue \
                                 SET status = $1, attempts = $2, last_error = $3, \
                                     next_attempt_at = NOW() + ($4::text || ' seconds')::interval, updated_at = NOW() \
                                 WHERE id = $5"
                            )
                            .bind(status)
                            .bind(next_attempts)
                            .bind(e.to_string())
                            .bind(backoff_secs.to_string())
                            .bind(id)
                            .execute(&db)
                            .await;
                        }
                    }
                }

                tokio::time::sleep(tick).await;
            }
        });
    }

    pub async fn enqueue_event(
        &self,
        tenant_id: Uuid,
        session_id: Option<Uuid>,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> anyhow::Result<()> {
        if self.endpoints.is_empty() {
            return Ok(());
        }
        for endpoint in &self.endpoints {
            sqlx::query(
                "INSERT INTO witness_webhook_queue (tenant_id, session_id, endpoint, event_type, payload, status) \
                 VALUES ($1, $2, $3, $4, $5, 'pending')"
            )
            .bind(tenant_id)
            .bind(session_id)
            .bind(endpoint)
            .bind(event_type)
            .bind(payload)
            .execute(&self.db)
            .await?;
        }
        Ok(())
    }
}

