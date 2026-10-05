use std::sync::Arc;
use crate::state::PlatformState;

/// OPS-07: Background webhook retry loop.
/// Polls `webhook_retry` for due `queued` items, POSTs them, then applies
/// exponential backoff or dead-letter. Runs every 30 seconds.
pub fn spawn_webhook_retry_loop(state: Arc<PlatformState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let summary = tokio::task::spawn_blocking({
                let state = state.clone();
                move || crate::services::webhooks::process_due_webhook_retries(&state)
            })
            .await;
            match summary {
                Ok((delivered, failed, dead)) if delivered + failed + dead > 0 => {
                    tracing::info!(
                        delivered = delivered,
                        failed = failed,
                        dead_letter = dead,
                        "[webhook_retry] cycle complete"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "[webhook_retry] worker join failed"),
            }
        }
    });
}

pub fn spawn_hitl_timeout_loop(state: Arc<PlatformState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            let expired = {
                crate::services::agents::hitl_ensure_hydrated(&state);
                crate::services::agents::sweep_expired_hitl_requests(&state)
            };
            if expired > 0 {
                tracing::info!(expired = expired, "[hitl_timeout] expired pending HITL requests");
            }
        }
    });
}

/// P8.4: periodic mesh peer probe + durable peer ACK (30s).
pub fn spawn_membership_probe_loop(state: Arc<PlatformState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let cell = state.storage_layout.cell_id.clone();
            let _ = crate::services::membership_heartbeat::probe_and_tick(
                Some(state.as_ref()),
                &cell,
            )
            .await;
        }
    });
}

/// WF-01 scaffold: poll ENABLED workflows and durably consume one synthetic CNP
/// enable-event each cycle. Not a live bus consumer — honesty stays explicit.
pub fn spawn_workflow_cnp_dispatch_poller(state: Arc<PlatformState>) {
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(45)).await;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let n = match tokio::task::spawn_blocking({
                let state = state.clone();
                move || crate::services::workflow_cnp::poll_consume_one_synthetic_event(&state)
            })
            .await
            {
                Ok(n) => n,
                Err(_) => 0,
            };
            if n > 0 {
                tracing::info!(consumed = n, "[wf_cnp_poller] consumed synthetic enable events");
            }
        }
    });
}

/// Durable CLS blueprint runner: claim a lease, execute admitted steps, retry/DLQ.
pub fn spawn_workflow_runner_loop(state: Arc<PlatformState>) {
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(8)).await;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            let n = match tokio::task::spawn_blocking({
                let state = state.clone();
                move || crate::services::workflow_runner::tick_once(&state)
            })
            .await
            {
                Ok(n) => n,
                Err(_) => 0,
            };
            if n > 0 {
                tracing::info!(claimed = n, "[wf_runner] processed durable run lease");
            }
        }
    });
}

/// X.9: Background notification escalation loop.
/// Calls the same escalation logic that POST /notifications/scan uses,
/// but autonomously every 5 minutes — no human trigger needed.
pub fn spawn_notification_escalator(state: Arc<PlatformState>) {
    tokio::spawn(async move {
        // Stagger start by 60s so it doesn't race with server startup
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let llm_wired = crate::util_lock::rwlock_read(&state.llm_router, "llm_router")
                .map(|g| g.is_some())
                .unwrap_or(false);

            // FIX BUG-033: Scan for new notifications - kernel data collected inside scan_platform
            let new_notifications = {
                let k = match crate::util_lock::mutex_lock(&state.kernel, "kernel") {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::error!(error = %e, "[notifications] skip cycle");
                        continue;
                    }
                };
                let es = match crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::error!(error = %e, "[notifications] skip cycle");
                        continue;
                    }
                };
                crate::services::notifications::scan_platform(&k, &**es, llm_wired)
            };

            let mut es = match crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!(error = %e, "[notifications] skip store");
                    continue;
                }
            };
            let mut new_count = 0usize;
            let mut escalated = 0usize;

            // Store + deliver new ones
            for mut n in new_notifications {
                deliver_and_store(&mut n, &mut **es);
                new_count += 1;
            }

            // Escalation pass on existing stored notifications
            let existing = load_all_notifications(&**es);
            let now_ms = chrono::Utc::now().timestamp_millis();
            for mut n in existing {
                if n.get("status").and_then(|s| s.as_str())
                    .map(|s| s != "PENDING" && s != "DELIVERED").unwrap_or(true)
                {
                    continue;
                }
                let next_esc = match n.get("next_escalation").and_then(|v| v.as_str()) {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&next_esc) {
                    if dt.timestamp_millis() <= now_ms {
                        // Escalate severity
                        let cur_sev = n.get("severity").and_then(|s| s.as_str()).unwrap_or("INFO");
                        let new_sev = match cur_sev {
                            "INFO"     => "WARNING",
                            "WARNING"  => "CRITICAL",
                            _          => "PAGED",
                        };
                        let next_window_ms = now_ms + match new_sev {
                            "WARNING"  => 4 * 3_600_000_i64,
                            "CRITICAL" => 2 * 3_600_000_i64,
                            _          => 3_600_000_i64,
                        };
                        let next_esc_iso = chrono::DateTime::from_timestamp_millis(next_window_ms)
                            .map(|d| d.to_rfc3339())
                            .unwrap_or_default();

                        if let Some(obj) = n.as_object_mut() {
                            obj.insert("severity".into(), serde_json::json!(new_sev));
                            obj.insert("status".into(), serde_json::json!("ESCALATED"));
                            obj.insert("next_escalation".into(), serde_json::json!(next_esc_iso));
                            let count = obj.get("escalation_count")
                                .and_then(|v| v.as_u64()).unwrap_or(0) + 1;
                            obj.insert("escalation_count".into(), serde_json::json!(count));

                            if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
                                let id = id.to_string();
                                let _ = es.folder_put("notifications", &id, &n);
                            }
                        }
                        escalated += 1;
                    }
                }
            }

            if new_count > 0 || escalated > 0 {
                tracing::info!(
                    new = new_count,
                    escalated = escalated,
                    "[notification_escalator] cycle complete"
                );
            }
        }
    });
}

fn deliver_and_store(
    n: &mut crate::services::notifications::Notification,
    es: &mut (dyn connector_engine::engine_store::EngineStore + Send),
) {
    let _ = es.folder_put(
        "notifications",
        &n.id,
        &serde_json::to_value(&*n).unwrap_or_default(),
    );
    let log_key = format!("{}_{}", n.id, chrono::Utc::now().timestamp_millis());
    let _ = es.folder_put("notification_log", &log_key, &serde_json::json!({
        "notification_id":   n.id,
        "notification_type": n.notification_type,
        "severity":          n.severity,
        "title":             n.title,
        "emitted_at":        chrono::Utc::now().to_rfc3339(),
        "source":            "background_escalator",
    }));
}

fn load_all_notifications(
    es: &(dyn connector_engine::engine_store::EngineStore + Send),
) -> Vec<serde_json::Value> {
    let keys = es.folder_keys("notifications", None).unwrap_or_default();
    keys.iter()
        .filter_map(|k| es.folder_get("notifications", k).ok().flatten())
        .collect()
}

/// FIX BUG-039: Background escrow expiration loop.
/// Automatically expires stale escrows and returns funds to requesters.
/// Runs every 60 seconds to ensure funds aren't locked forever.
pub fn spawn_escrow_expiration_loop(state: Arc<PlatformState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let expired = {
                let mut em = state.escrow.lock().unwrap();
                em.expire_stale(now_ms)
            };
            if !expired.is_empty() {
                tracing::info!(
                    count = expired.len(),
                    escrow_ids = ?expired,
                    "[escrow_expiration] expired stale escrows, funds returned to requesters"
                );
            }
        }
    });
}
