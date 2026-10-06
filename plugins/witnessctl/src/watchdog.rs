use sqlx::PgPool;

pub fn start_proxy_watchdog(
    db: PgPool,
    route_profile: String,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let tick = std::time::Duration::from_secs(interval_secs.max(5));
        loop {
            let active_session_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(1) FROM witness_sessions WHERE status = 'active'"
            )
            .fetch_one(&db)
            .await
            .unwrap_or(0);
            let healthy = sqlx::query("SELECT 1")
                .fetch_one(&db)
                .await
                .is_ok();
            let note = if healthy {
                "watchdog heartbeat ok"
            } else {
                "watchdog heartbeat degraded"
            };
            let _ = sqlx::query(
                "INSERT INTO witness_proxy_watchdog (service_name, route_profile, healthy, active_session_count, note, heartbeat_at) \
                 VALUES ($1, $2, $3, $4, $5, NOW())"
            )
            .bind("witnessctl-proxy")
            .bind(&route_profile)
            .bind(healthy)
            .bind(active_session_count)
            .bind(note)
            .execute(&db)
            .await;

            tokio::time::sleep(tick).await;
        }
    });
}
