//! Storage layer for TraceTramp
//!
//! Postgres for persistent data, Redis for sessions/caching/queues

use redis::{aio::ConnectionManager, Client as RedisClient};
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tracing::{error, info, warn};

use crate::error::AppError;

/// Embedded migrations (checksum validation on every `run`).
pub static TRACETRAMP_MIGRATOR: Migrator = sqlx::migrate!("./migrations");

fn migration_checksum_repair_allowed() -> bool {
    std::env::var("TRACETRAMP_ALLOW_MIGRATION_CHECKSUM_REPAIR")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

async fn repair_applied_migration_checksum(pool: &PgPool, version: i64) -> Result<(), AppError> {
    let migration = TRACETRAMP_MIGRATOR.iter().find(|m| m.version == version);
    let Some(m) = migration else {
        return Err(AppError::Database(format!(
            "checksum repair: no embedded migration for version {}",
            version
        )));
    };
    let rows = sqlx::query(
        r#"UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2 AND success = true"#,
    )
    .bind(m.checksum.as_ref())
    .bind(version)
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(format!("checksum repair update: {}", e)))?
    .rows_affected();
    if rows == 0 {
        return Err(AppError::Database(format!(
            "checksum repair: no successful row for migration version {}",
            version
        )));
    }
    warn!(
        "TRACETRAMP_ALLOW_MIGRATION_CHECKSUM_REPAIR: updated _sqlx_migrations.checksum for version {} to match current migration files (DEV / recovery only — remove the env var after success)",
        version
    );
    Ok(())
}

/// Run embedded migrations; optionally repair checksum drift for already-applied revisions.
pub async fn run_tracetramp_migrations(pool: &PgPool) -> Result<(), AppError> {
    let allow_repair = migration_checksum_repair_allowed();
    let mut repairs = 0u32;
    loop {
        match TRACETRAMP_MIGRATOR.run(pool).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if allow_repair {
                    if let MigrateError::VersionMismatch(version) = &e {
                        repairs += 1;
                        if repairs > 64 {
                            return Err(AppError::Database(
                                "migration checksum repair: too many iterations".to_string(),
                            ));
                        }
                        repair_applied_migration_checksum(pool, *version).await?;
                        continue;
                    }
                }
                if let MigrateError::VersionMismatch(version) = &e {
                    error!(
                        "Migration checksum mismatch for version {} (applied migration file changed). \
                         This is unsafe in production. For a one-time DEV repair only, set \
                         TRACETRAMP_ALLOW_MIGRATION_CHECKSUM_REPAIR=1, start once, verify, then unset the variable. \
                         Error: {}",
                        version, e
                    );
                } else {
                    error!("Migration failed: {}", e);
                }
                return Err(AppError::Database(format!("Migration failed: {}", e)));
            }
        }
    }
}

fn flag_on(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

/// Production keeps rows only when this is set. A normal restart clears them.
pub fn keep_records(service_flag: Option<&str>, shared_flag: Option<&str>) -> bool {
    flag_on(service_flag) || flag_on(shared_flag)
}

fn keep_records_from_env() -> bool {
    keep_records(
        std::env::var("TRACETRAMP_KEEP_RECORDS").ok().as_deref(),
        std::env::var("CONNECTOR_KEEP_RECORDS").ok().as_deref(),
    )
}

const CLEAR_PUBLIC_TABLES_SQL: &str = r#"
DO $$
DECLARE stmt text;
BEGIN
  SELECT 'TRUNCATE TABLE '
      || string_agg(format('%I.%I', schemaname, tablename), ', ')
      || ' RESTART IDENTITY CASCADE'
    INTO stmt
  FROM pg_tables
  WHERE schemaname = 'public'
    AND tablename <> '_sqlx_migrations';
  IF stmt IS NOT NULL THEN
    EXECUTE stmt;
  END IF;
END $$;
"#;

/// Drop TraceTramp rows and the Redis cache unless production asked to keep them.
/// Schema and applied migrations stay. The next start is an empty ledger.
pub async fn reset_on_restart(
    pool: &PgPool,
    redis: Option<&mut ConnectionManager>,
) -> Result<(), AppError> {
    if keep_records_from_env() {
        info!("TRACETRAMP_KEEP_RECORDS is set — TraceTramp rows survive this restart");
        return Ok(());
    }
    sqlx::query(CLEAR_PUBLIC_TABLES_SQL)
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(format!("restart clear failed: {e}")))?;
    info!("TraceTramp restart cleared database rows");
    if let Some(conn) = redis {
        redis::cmd("FLUSHDB")
            .query_async::<_, String>(conn)
            .await
            .map_err(|e| AppError::Redis(format!("restart flush failed: {e}")))?;
        info!("TraceTramp restart cleared Redis");
    }
    Ok(())
}

/// Initialize PostgreSQL connection pool
pub async fn init_postgres(database_url: &str) -> Result<PgPool, AppError> {
    use sqlx::postgres::{PgConnectOptions, PgSslMode};
    use std::str::FromStr;

    info!("Initializing PostgreSQL connection pool...");

    // Fly Postgres (internal 6PN) is plain TCP — disable TLS by default to
    // avoid the "unexpected end of file" SSL-negotiation failure.
    // Override with TRACETRAMP_SSL_MODE=require|prefer if needed.
    let ssl_mode = std::env::var("TRACETRAMP_SSL_MODE")
        .ok()
        .and_then(|v| match v.to_ascii_lowercase().as_str() {
            "require" => Some(PgSslMode::Require),
            "prefer"  => Some(PgSslMode::Prefer),
            "disable" => Some(PgSslMode::Disable),
            _ => None,
        })
        .unwrap_or(PgSslMode::Disable);

    let connect_opts = PgConnectOptions::from_str(database_url)
        .map(|o| o.ssl_mode(ssl_mode))
        .unwrap_or_else(|_| {
            PgConnectOptions::from_str(database_url)
                .expect("invalid TRACETRAMP_DATABASE_URL")
        });

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(600))
        .connect_with(connect_opts)
        .await
        .map_err(|e| {
            error!("Failed to connect to PostgreSQL: {}", e);
            AppError::Database(format!("Failed to connect: {}", e))
        })?;
    
    // Run migrations (optional checksum repair: see `run_tracetramp_migrations`)
    info!("Running database migrations...");
    run_tracetramp_migrations(&pool).await?;
    
    info!("PostgreSQL initialized successfully");
    Ok(pool)
}

/// Initialize Redis when configured; otherwise `None` (PostgreSQL approvals only).
pub async fn init_redis_optional(redis_url: Option<&str>) -> Result<Option<ConnectionManager>, AppError> {
    let Some(url) = redis_url.filter(|u| {
        let t = u.trim().to_ascii_lowercase();
        !t.is_empty() && t != "off" && t != "disabled" && t != "none"
    }) else {
        info!("Redis disabled — using PostgreSQL approval_queue (set TRACETRAMP_REDIS_URL to enable)");
        return Ok(None);
    };

    info!("Initializing Redis connection...");
    let client = RedisClient::open(url).map_err(|e| {
        error!("Failed to create Redis client: {}", e);
        AppError::Redis(format!("Failed to create client: {}", e))
    })?;
    let manager = ConnectionManager::new(client)
        .await
        .map_err(|e| {
            error!("Failed to create Redis connection manager: {}", e);
            AppError::Redis(format!("Failed to create manager: {}", e))
        })?;
    info!("Redis initialized successfully");
    Ok(Some(manager))
}

/// Initialize Redis connection manager (required URL).
pub async fn init_redis(redis_url: &str) -> Result<ConnectionManager, AppError> {
    init_redis_optional(Some(redis_url))
        .await?
        .ok_or_else(|| AppError::Redis("redis URL missing or disabled".to_string()))
}

/// Cache tenant configuration in Redis
pub async fn cache_tenant_config(
    redis: &mut ConnectionManager,
    tenant_id: &str,
    config: &serde_json::Value,
    ttl_seconds: u64,
) -> Result<(), AppError> {
    let key = crate::tenancy::tenant_redis_config_key(tenant_id);
    let value = serde_json::to_string(config)?;
    
    redis::cmd("SETEX")
        .arg(&key)
        .arg(ttl_seconds)
        .arg(&value)
        .query_async(redis)
        .await
        .map_err(|e| AppError::Redis(e.to_string()))?;
    
    Ok(())
}

/// Get cached tenant configuration
pub async fn get_cached_tenant_config(
    redis: &mut ConnectionManager,
    tenant_id: &str,
) -> Result<Option<serde_json::Value>, AppError> {
    let key = crate::tenancy::tenant_redis_config_key(tenant_id);
    
    let value: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(redis)
        .await
        .map_err(|e| AppError::Redis(e.to_string()))?;
    
    match value {
        Some(v) => {
            let config = serde_json::from_str(&v)?;
            Ok(Some(config))
        }
        None => Ok(None),
    }
}

/// Add request to approval queue
pub async fn enqueue_approval(
    redis: &mut ConnectionManager,
    request_id: &str,
    approvers: &[String],
) -> Result<(), AppError> {
    let queue_key = "approval:queue";
    let item = serde_json::json!({
        "request_id": request_id,
        "approvers": approvers,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    
    redis::cmd("LPUSH")
        .arg(queue_key)
        .arg(item.to_string())
        .query_async(redis)
        .await
        .map_err(|e| AppError::Redis(e.to_string()))?;
    
    Ok(())
}

#[cfg(test)]
mod keep_records_tests {
    use super::keep_records;

    #[test]
    fn a_normal_restart_does_not_keep_records() {
        assert!(!keep_records(None, None));
        assert!(!keep_records(Some("0"), Some("")));
        assert!(!keep_records(Some("false"), None));
    }

    #[test]
    fn production_can_keep_records() {
        assert!(keep_records(Some("1"), None));
        assert!(keep_records(None, Some("true")));
        assert!(keep_records(Some("yes"), Some("0")));
    }
}

