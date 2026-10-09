/// Postgres persistence layer for the license server (sqlx async).
///
/// Schema lives in migrations/0001_initial.sql — applied automatically at startup.
/// All methods are async; Db wraps PgPool which is cheaply Clone (Arc inside).
///
/// Tables:
///   license_keys, activations, usage_records, revocation_log
///   customers, instances, surveillance_events, blocked_hashes
///   binary_issuances, rpc_tokens, portal_users, pilot_grants

use sqlx::{PgPool, postgres::PgPoolOptions, Row};
use crate::types::*;
use crate::database::*;

// ── Db handle ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    pub async fn connect(database_url: &str) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await
            .unwrap_or_else(|e| panic!("[persist] Cannot connect to Postgres: {}", e));

        eprintln!("[persist] Connected to Postgres");

        // Run migrations (idempotent)
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap_or_else(|e| panic!("[persist] Migration failed: {}", e));

        eprintln!("[persist] Schema ready");
        Self { pool }
    }

    // ── License Keys ──────────────────────────────────────────────────────────

    pub async fn upsert_key(&self, k: &LicenseKey) {
        let active = serde_json::to_value(&k.active_instances).unwrap_or_default();
        let result = sqlx::query(
            r#"INSERT INTO license_keys
               (key_id, key_secret, tier, customer_email, customer_name,
                issued_at, expires_at, max_activations, revoked, stripe_sub_id,
                signature, active_instances)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
               ON CONFLICT (key_id) DO UPDATE SET
                 revoked           = EXCLUDED.revoked,
                 active_instances  = EXCLUDED.active_instances,
                 stripe_sub_id     = EXCLUDED.stripe_sub_id,
                 expires_at        = EXCLUDED.expires_at,
                 max_activations   = EXCLUDED.max_activations"#,
        )
        .bind(&k.key_id)
        .bind(&k.key_secret)
        .bind(format!("{:?}", k.tier))
        .bind(&k.customer_email)
        .bind(&k.customer_name)
        .bind(parse_ts(&k.issued_at))
        .bind(k.expires_at.as_deref().and_then(|s| parse_ts(s)))
        .bind(k.max_activations as i32)
        .bind(k.revoked)
        .bind(&k.stripe_subscription_id)
        .bind(&k.signature)
        .bind(active)
        .execute(&self.pool)
        .await;
        if let Err(e) = result { eprintln!("[persist] upsert_key: {}", e); }
    }

    pub async fn load_all_keys(&self) -> Vec<LicenseKey> {
        sqlx::query(
            "SELECT key_id, key_secret, tier, customer_email, customer_name,
                    issued_at, expires_at, max_activations, revoked, stripe_sub_id,
                    signature, active_instances
             FROM license_keys"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| LicenseKey {
            key_id:                 row.get("key_id"),
            key_secret:             row.get("key_secret"),
            tier:                   Tier::from_str(&row.get::<String, _>("tier")),
            customer_email:         row.get("customer_email"),
            customer_name:          row.get("customer_name"),
            issued_at:              fmt_ts(row.get("issued_at")),
            expires_at:             row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at").map(|t| t.to_rfc3339()),
            max_activations:        row.get::<i32, _>("max_activations") as u32,
            revoked:                row.get("revoked"),
            stripe_subscription_id: row.get("stripe_sub_id"),
            signature:              row.get("signature"),
            active_instances:       row.get::<serde_json::Value, _>("active_instances")
                                       .as_array().cloned().unwrap_or_default()
                                       .into_iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
        })
        .collect()
    }

    pub async fn revoke_key(&self, key_id: &str, reason: Option<&str>) {
        let r1 = sqlx::query("UPDATE license_keys SET revoked=true WHERE key_id=$1")
            .bind(key_id).execute(&self.pool).await;
        let r2 = sqlx::query("INSERT INTO revocation_log (key_id, reason) VALUES ($1,$2)")
            .bind(key_id).bind(reason).execute(&self.pool).await;
        for r in [r1.err(), r2.err()].into_iter().flatten() {
            eprintln!("[persist] revoke_key: {}", r);
        }
    }

    pub async fn update_key_instances(&self, key_id: &str, instances: &[String]) {
        let v = serde_json::to_value(instances).unwrap_or_default();
        let r = sqlx::query("UPDATE license_keys SET active_instances=$1 WHERE key_id=$2")
            .bind(v).bind(key_id).execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] update_key_instances: {}", e); }
    }

    // ── Activations ───────────────────────────────────────────────────────────

    pub async fn upsert_activation(&self, a: &Activation) {
        let r = sqlx::query(
            r#"INSERT INTO activations
               (instance_id, key_id, machine_id, hostname, activated_at, last_heartbeat, deactivated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7)
               ON CONFLICT (instance_id) DO UPDATE SET
                 last_heartbeat = EXCLUDED.last_heartbeat,
                 deactivated_at = EXCLUDED.deactivated_at"#,
        )
        .bind(&a.instance_id).bind(&a.key_id).bind(&a.machine_id).bind(&a.hostname)
        .bind(parse_ts(&a.activated_at))
        .bind(a.last_heartbeat.as_deref().and_then(|s| parse_ts(s)))
        .bind(a.deactivated_at.as_deref().and_then(|s| parse_ts(s)))
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] upsert_activation: {}", e); }
    }

    pub async fn load_all_activations(&self) -> Vec<Activation> {
        sqlx::query(
            "SELECT instance_id, key_id, machine_id, hostname,
                    activated_at, last_heartbeat, deactivated_at
             FROM activations"
        )
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| Activation {
            instance_id:    row.get("instance_id"),
            key_id:         row.get("key_id"),
            machine_id:     row.get("machine_id"),
            hostname:       row.get("hostname"),
            activated_at:   fmt_ts(row.get("activated_at")),
            last_heartbeat: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_heartbeat").map(|t| t.to_rfc3339()),
            deactivated_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("deactivated_at").map(|t| t.to_rfc3339()),
        })
        .collect()
    }

    pub async fn record_usage(&self, u: &UsageRecord) {
        let r = sqlx::query(
            r#"INSERT INTO usage_records
               (instance_id, agents_active, packets_stored, audit_entries, total_tokens, total_cost_usd)
               VALUES ($1,$2,$3,$4,$5,$6)"#,
        )
        .bind(&u.instance_id)
        .bind(u.agents_active as i32)
        .bind(u.packets_stored as i32)
        .bind(u.audit_entries as i32)
        .bind(u.total_tokens as i64)
        .bind(u.total_cost_usd)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] record_usage: {}", e); }
    }

    pub async fn usage_for_instance(&self, instance_id: &str) -> Vec<UsageRecord> {
        sqlx::query(
            "SELECT instance_id, recorded_at, agents_active, packets_stored,
                    audit_entries, total_tokens, total_cost_usd
             FROM usage_records WHERE instance_id=$1 ORDER BY id DESC LIMIT 200"
        )
        .bind(instance_id)
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| UsageRecord {
            instance_id:    row.get("instance_id"),
            timestamp:      fmt_ts(row.get("recorded_at")),
            agents_active:  row.get::<i32, _>("agents_active") as usize,
            packets_stored: row.get::<i32, _>("packets_stored") as usize,
            audit_entries:  row.get::<i32, _>("audit_entries") as usize,
            total_tokens:   row.get::<i64, _>("total_tokens") as u64,
            total_cost_usd: row.get("total_cost_usd"),
        })
        .collect()
    }

    // ── Customers ─────────────────────────────────────────────────────────────

    pub async fn upsert_customer(&self, c: &CustomerRecord) {
        let key_ids = serde_json::to_value(&c.key_ids).unwrap_or_default();
        let r = sqlx::query(
            r#"INSERT INTO customers
               (customer_id, email, name, stripe_customer_id, created_at,
                payment_status, last_payment_at, total_paid_cents, key_ids)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
               ON CONFLICT (customer_id) DO UPDATE SET
                 name               = EXCLUDED.name,
                 stripe_customer_id = EXCLUDED.stripe_customer_id,
                 payment_status     = EXCLUDED.payment_status,
                 last_payment_at    = EXCLUDED.last_payment_at,
                 total_paid_cents   = EXCLUDED.total_paid_cents,
                 key_ids            = EXCLUDED.key_ids"#,
        )
        .bind(&c.customer_id).bind(&c.email).bind(&c.name)
        .bind(&c.stripe_customer_id)
        .bind(parse_ts(&c.created_at))
        .bind(format!("{:?}", c.payment_status))
        .bind(c.last_payment_at.as_deref().and_then(|s| parse_ts(s)))
        .bind(c.total_paid_cents as i64)
        .bind(key_ids)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] upsert_customer: {}", e); }
    }

    pub async fn load_all_customers(&self) -> Vec<CustomerRecord> {
        sqlx::query(
            "SELECT customer_id, email, name, stripe_customer_id, created_at,
                    payment_status, last_payment_at, total_paid_cents, key_ids
             FROM customers"
        )
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| CustomerRecord {
            customer_id:        row.get("customer_id"),
            email:              row.get("email"),
            name:               row.get("name"),
            stripe_customer_id: row.get("stripe_customer_id"),
            created_at:         fmt_ts(row.get("created_at")),
            payment_status:     payment_status_from_str(&row.get::<String, _>("payment_status")),
            last_payment_at:    row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_payment_at").map(|t| t.to_rfc3339()),
            total_paid_cents:   row.get::<i64, _>("total_paid_cents") as u64,
            key_ids:            row.get::<serde_json::Value, _>("key_ids")
                                   .as_array().cloned().unwrap_or_default()
                                   .into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        })
        .collect()
    }

    // ── Instances ─────────────────────────────────────────────────────────────

    pub async fn upsert_instance(&self, i: &InstanceRecord) {
        let perms = serde_json::to_value(&i.permissions).unwrap_or_default();
        let r = sqlx::query(
            r#"INSERT INTO instances
               (instance_id, key_id, customer_id, machine_id, hostname, binary_hash, binary_id,
                license_address, tier, permissions, activated_at, last_heartbeat, last_usage_report,
                status, agents_last, packets_last, trust_score_last, total_tokens, total_cost,
                warnings_issued, grace_period_ends, kill_issued)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
               ON CONFLICT (instance_id) DO UPDATE SET
                 last_heartbeat    = EXCLUDED.last_heartbeat,
                 last_usage_report = EXCLUDED.last_usage_report,
                 status            = EXCLUDED.status,
                 agents_last       = EXCLUDED.agents_last,
                 packets_last      = EXCLUDED.packets_last,
                 trust_score_last  = EXCLUDED.trust_score_last,
                 total_tokens      = EXCLUDED.total_tokens,
                 total_cost        = EXCLUDED.total_cost,
                 warnings_issued   = EXCLUDED.warnings_issued,
                 grace_period_ends = EXCLUDED.grace_period_ends,
                 kill_issued       = EXCLUDED.kill_issued,
                 permissions       = EXCLUDED.permissions"#,
        )
        .bind(&i.instance_id).bind(&i.key_id).bind(&i.customer_id)
        .bind(&i.machine_id).bind(&i.hostname).bind(&i.binary_hash)
        .bind(&i.binary_id).bind(&i.license_address).bind(&i.tier)
        .bind(perms)
        .bind(parse_ts(&i.activated_at))
        .bind(i.last_heartbeat.as_deref().and_then(|s| parse_ts(s)))
        .bind(i.last_usage_report.as_deref().and_then(|s| parse_ts(s)))
        .bind(format!("{:?}", i.status))
        .bind(i.agents_last as i32).bind(i.packets_last as i32)
        .bind(i.trust_score_last as i32)
        .bind(i.total_tokens_lifetime as i64)
        .bind(i.total_cost_lifetime)
        .bind(i.warnings_issued as i32)
        .bind(i.grace_period_ends.as_deref().and_then(|s| parse_ts(s)))
        .bind(i.kill_issued)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] upsert_instance: {}", e); }
    }

    pub async fn load_all_instances(&self) -> Vec<InstanceRecord> {
        sqlx::query(
            "SELECT instance_id, key_id, customer_id, machine_id, hostname, binary_hash, binary_id,
                    license_address, tier, permissions, activated_at, last_heartbeat, last_usage_report,
                    status, agents_last, packets_last, trust_score_last, total_tokens, total_cost,
                    warnings_issued, grace_period_ends, kill_issued
             FROM instances"
        )
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| InstanceRecord {
            instance_id:           row.get("instance_id"),
            key_id:                row.get("key_id"),
            customer_id:           row.get("customer_id"),
            machine_id:            row.get("machine_id"),
            hostname:              row.get("hostname"),
            binary_hash:           row.get("binary_hash"),
            binary_id:             row.get("binary_id"),
            license_address:       row.get("license_address"),
            tier:                  row.get("tier"),
            permissions:           row.get::<serde_json::Value, _>("permissions")
                                      .as_array().cloned().unwrap_or_default()
                                      .into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
            activated_at:          fmt_ts(row.get("activated_at")),
            last_heartbeat:        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_heartbeat").map(|t| t.to_rfc3339()),
            last_usage_report:     row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_usage_report").map(|t| t.to_rfc3339()),
            status:                instance_status_from_str(&row.get::<String, _>("status")),
            agents_last:           row.get::<i32, _>("agents_last") as u32,
            packets_last:          row.get::<i32, _>("packets_last") as u32,
            trust_score_last:      row.get::<i32, _>("trust_score_last") as u32,
            total_tokens_lifetime: row.get::<i64, _>("total_tokens") as u64,
            total_cost_lifetime:   row.get("total_cost"),
            warnings_issued:       row.get::<i32, _>("warnings_issued") as u32,
            grace_period_ends:     row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("grace_period_ends").map(|t| t.to_rfc3339()),
            kill_issued:           row.get("kill_issued"),
        })
        .collect()
    }

    // ── Surveillance events ───────────────────────────────────────────────────

    pub async fn log_event(&self, e: &SurveillanceEvent) {
        let details = serde_json::to_value(&e.details).unwrap_or_default();
        let r = sqlx::query(
            r#"INSERT INTO surveillance_events
               (event_id, instance_id, event_type, details)
               VALUES ($1,$2,$3,$4)
               ON CONFLICT (event_id) DO NOTHING"#,
        )
        .bind(&e.event_id)
        .bind(&e.instance_id)
        .bind(format!("{:?}", e.event_type))
        .bind(details)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] log_event: {}", e); }
    }

    pub async fn load_recent_events(&self, limit: usize) -> Vec<SurveillanceEvent> {
        sqlx::query(
            "SELECT event_id, instance_id, event_type, occurred_at, details
             FROM surveillance_events ORDER BY id DESC LIMIT $1"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| SurveillanceEvent {
            event_id:    row.get("event_id"),
            instance_id: row.get("instance_id"),
            event_type:  surveillance_event_type_from_str(&row.get::<String, _>("event_type")),
            timestamp:   fmt_ts(row.get("occurred_at")),
            details:     row.get::<serde_json::Value, _>("details")
                            .as_object().cloned().map(|m| m.into_iter().collect()).unwrap_or_default(),
        })
        .collect()
    }

    pub async fn is_binary_blocked(&self, hash: &str) -> bool {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM blocked_hashes WHERE hash=$1")
            .bind(hash).fetch_one(&self.pool).await.unwrap_or(0) > 0
    }

    pub async fn block_binary(&self, hash: &str, reason: &str) {
        let r = sqlx::query(
            "INSERT INTO blocked_hashes (hash, reason) VALUES ($1,$2) ON CONFLICT (hash) DO NOTHING"
        )
        .bind(hash).bind(reason).execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] block_binary: {}", e); }
    }

    pub async fn total_event_count(&self) -> usize {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM surveillance_events")
            .fetch_one(&self.pool).await.unwrap_or(0) as usize
    }

    // ── Binary Issuances ─────────────────────────────────────────────────────

    pub async fn upsert_issuance(&self, i: &crate::rpc_token::BinaryIssuance) {
        let tids = serde_json::to_value(&i.active_token_ids).unwrap_or_default();
        let r = sqlx::query(
            r#"INSERT INTO binary_issuances
               (binary_id, role_id, secret_id, secret_id_used, key_id, tier,
                locked_machine_id, expires_at, auth_count, active_token_ids)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
               ON CONFLICT (binary_id) DO UPDATE SET
                 secret_id_used   = EXCLUDED.secret_id_used,
                 locked_machine_id= EXCLUDED.locked_machine_id,
                 auth_count       = EXCLUDED.auth_count,
                 active_token_ids = EXCLUDED.active_token_ids"#,
        )
        .bind(&i.binary_id).bind(&i.role_id).bind(&i.secret_id)
        .bind(i.secret_id_used).bind(&i.key_id).bind(&i.tier)
        .bind(&i.locked_machine_id)
        .bind(i.expires_at.as_deref().and_then(|s| parse_ts(s)))
        .bind(i.auth_count as i32).bind(tids)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] upsert_issuance: {}", e); }
    }

    pub async fn load_all_issuances(&self) -> Vec<crate::rpc_token::BinaryIssuance> {
        sqlx::query(
            "SELECT binary_id, role_id, secret_id, secret_id_used, key_id, tier,
                    locked_machine_id, issued_at, expires_at, auth_count, active_token_ids
             FROM binary_issuances"
        )
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| crate::rpc_token::BinaryIssuance {
            binary_id:         row.get("binary_id"),
            role_id:           row.get("role_id"),
            secret_id:         row.get("secret_id"),
            secret_id_used:    row.get("secret_id_used"),
            key_id:            row.get("key_id"),
            tier:              row.get("tier"),
            locked_machine_id: row.get("locked_machine_id"),
            issued_at:         fmt_ts(row.get("issued_at")),
            expires_at:        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at").map(|t| t.to_rfc3339()),
            auth_count:        row.get::<i32, _>("auth_count") as u32,
            active_token_ids:  row.get::<serde_json::Value, _>("active_token_ids")
                                  .as_array().cloned().unwrap_or_default()
                                  .into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        })
        .collect()
    }

    // ── RPC Tokens ────────────────────────────────────────────────────────────

    pub async fn record_token_issued(&self, token_id: &str, instance_id: &str, binary_id: &str, expires_at: i64) {
        let r = sqlx::query(
            "INSERT INTO rpc_tokens (token_id, instance_id, binary_id, expires_at)
             VALUES ($1,$2,$3,$4) ON CONFLICT (token_id) DO NOTHING"
        )
        .bind(token_id).bind(instance_id).bind(binary_id).bind(expires_at)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] record_token_issued: {}", e); }
    }

    pub async fn record_token_revoked(&self, token_id: &str, reason: Option<&str>) {
        let r = sqlx::query(
            "UPDATE rpc_tokens SET revoked=true, revoked_at=now(), revoke_reason=$1 WHERE token_id=$2"
        )
        .bind(reason).bind(token_id).execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] record_token_revoked: {}", e); }
    }

    pub async fn load_revoked_token_ids(&self) -> Vec<String> {
        let now_ts = chrono::Utc::now().timestamp();
        sqlx::query_scalar::<_, String>(
            "SELECT token_id FROM rpc_tokens WHERE revoked=true AND expires_at > $1"
        )
        .bind(now_ts)
        .fetch_all(&self.pool).await.unwrap_or_default()
    }

    // ── Portal Users ──────────────────────────────────────────────────────────

    pub async fn upsert_portal_user(&self, u: &crate::portal::PortalUser) {
        let api_keys     = serde_json::to_value(&u.api_keys).unwrap_or_default();
        let backup_codes = serde_json::to_value(&u.backup_codes).unwrap_or_default();
        let r = sqlx::query(
            r#"INSERT INTO portal_users
               (user_id, email, name, password_hash, created_at, last_login,
                totp_secret, totp_enabled, api_keys, license_key_id, tier,
                locked, email_verified, backup_codes)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
               ON CONFLICT (user_id) DO UPDATE SET
                 name           = EXCLUDED.name,
                 password_hash  = EXCLUDED.password_hash,
                 last_login     = EXCLUDED.last_login,
                 totp_secret    = EXCLUDED.totp_secret,
                 totp_enabled   = EXCLUDED.totp_enabled,
                 api_keys       = EXCLUDED.api_keys,
                 license_key_id = EXCLUDED.license_key_id,
                 tier           = EXCLUDED.tier,
                 locked         = EXCLUDED.locked,
                 email_verified = EXCLUDED.email_verified,
                 backup_codes   = EXCLUDED.backup_codes"#,
        )
        .bind(&u.user_id).bind(&u.email).bind(&u.name).bind(&u.password_hash)
        .bind(parse_ts(&u.created_at))
        .bind(u.last_login.as_deref().and_then(|s| parse_ts(s)))
        .bind(&u.totp_secret)
        .bind(u.totp_enabled)
        .bind(api_keys)
        .bind(&u.license_key_id)
        .bind(&u.tier)
        .bind(u.locked)
        .bind(u.email_verified)
        .bind(backup_codes)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] upsert_portal_user: {}", e); }
    }

    pub async fn load_all_portal_users(&self) -> Vec<crate::portal::PortalUser> {
        sqlx::query(
            "SELECT user_id, email, name, password_hash, created_at, last_login,
                    totp_secret, totp_enabled, api_keys, license_key_id, tier,
                    locked, email_verified, backup_codes
             FROM portal_users"
        )
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| crate::portal::PortalUser {
            user_id:        row.get("user_id"),
            email:          row.get("email"),
            name:           row.get("name"),
            password_hash:  row.get("password_hash"),
            created_at:     fmt_ts(row.get("created_at")),
            last_login:     row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_login").map(|t| t.to_rfc3339()),
            totp_secret:    row.get("totp_secret"),
            totp_enabled:   row.get("totp_enabled"),
            api_keys:       row.get::<serde_json::Value, _>("api_keys")
                               .as_array().cloned().unwrap_or_default()
                               .into_iter().filter_map(|v| serde_json::from_value(v).ok()).collect(),
            license_key_id: row.get("license_key_id"),
            tier:           row.get("tier"),
            locked:         row.get("locked"),
            email_verified: row.get("email_verified"),
            backup_codes:   row.get::<serde_json::Value, _>("backup_codes")
                               .as_array().cloned().unwrap_or_default()
                               .into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        })
        .collect()
    }

    // ── Pilot Grants ──────────────────────────────────────────────────────────

    pub async fn upsert_pilot_grant(&self, grant: &crate::pilots::PilotGrant) {
        let features = serde_json::to_value(&grant.features_override).unwrap_or_default();
        let r = sqlx::query(
            r#"INSERT INTO pilot_grants
               (grant_id, customer_id, granted_by, granted_at, expires_at, status,
                tier_override, agent_limit_override, packet_limit_override,
                features_override, reason, notes)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
               ON CONFLICT (grant_id) DO UPDATE SET
                 status                 = EXCLUDED.status,
                 tier_override          = EXCLUDED.tier_override,
                 agent_limit_override   = EXCLUDED.agent_limit_override,
                 packet_limit_override  = EXCLUDED.packet_limit_override,
                 features_override      = EXCLUDED.features_override,
                 notes                  = EXCLUDED.notes"#,
        )
        .bind(&grant.grant_id).bind(&grant.customer_id).bind(&grant.granted_by)
        .bind(parse_ts(&grant.granted_at))
        .bind(parse_ts(&grant.expires_at))
        .bind(format!("{:?}", grant.status))
        .bind(&grant.tier_override)
        .bind(grant.agent_limit_override.map(|v| v as i32))
        .bind(grant.packet_limit_override.map(|v| v as i64))
        .bind(features)
        .bind(&grant.reason).bind(&grant.notes)
        .execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] upsert_pilot_grant: {}", e); }
    }

    pub async fn load_all_pilot_grants(&self) -> Vec<crate::pilots::PilotGrant> {
        sqlx::query(
            "SELECT grant_id, customer_id, granted_by, granted_at, expires_at, status,
                    tier_override, agent_limit_override, packet_limit_override,
                    features_override, reason, notes
             FROM pilot_grants"
        )
        .fetch_all(&self.pool).await.unwrap_or_default()
        .into_iter()
        .map(|row| map_pilot_grant(&row))
        .collect()
    }

    pub async fn get_active_pilot_for_customer(&self, customer_id: &str) -> Option<crate::pilots::PilotGrant> {
        sqlx::query(
            "SELECT grant_id, customer_id, granted_by, granted_at, expires_at, status,
                    tier_override, agent_limit_override, packet_limit_override,
                    features_override, reason, notes
             FROM pilot_grants
             WHERE customer_id=$1 AND status='Active'
             ORDER BY expires_at DESC LIMIT 1"
        )
        .bind(customer_id)
        .fetch_optional(&self.pool).await.ok().flatten()
        .map(|row| map_pilot_grant(&row))
    }

    pub async fn expire_pilot_grant(&self, grant_id: &str) {
        let r = sqlx::query("UPDATE pilot_grants SET status='Expired' WHERE grant_id=$1")
            .bind(grant_id).execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] expire_pilot_grant: {}", e); }
    }

    pub async fn revoke_pilot_grant(&self, grant_id: &str, reason: &str) {
        let note = format!("Revoked: {}", reason);
        let r = sqlx::query(
            "UPDATE pilot_grants SET status='Revoked', notes=notes || E'\\n' || $2 WHERE grant_id=$1"
        )
        .bind(grant_id).bind(note).execute(&self.pool).await;
        if let Err(e) = r { eprintln!("[persist] revoke_pilot_grant: {}", e); }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_ts(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&chrono::Utc))
}

fn fmt_ts(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339()
}

fn map_pilot_grant(row: &sqlx::postgres::PgRow) -> crate::pilots::PilotGrant {
    let status_str: String = row.get("status");
    crate::pilots::PilotGrant {
        grant_id:              row.get("grant_id"),
        customer_id:           row.get("customer_id"),
        granted_by:            row.get("granted_by"),
        granted_at:            fmt_ts(row.get("granted_at")),
        expires_at:            fmt_ts(row.get("expires_at")),
        status: match status_str.as_str() {
            "Expired" => crate::pilots::PilotStatus::Expired,
            "Revoked" => crate::pilots::PilotStatus::Revoked,
            _         => crate::pilots::PilotStatus::Active,
        },
        tier_override:           row.get("tier_override"),
        agent_limit_override:    row.get::<Option<i32>, _>("agent_limit_override").map(|v| v as u32),
        packet_limit_override:   row.get::<Option<i64>, _>("packet_limit_override").map(|v| v as u64),
        features_override:       row.get::<serde_json::Value, _>("features_override")
                                    .as_array().cloned().unwrap_or_default()
                                    .into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        reason: row.get("reason"),
        notes:  row.get("notes"),
    }
}

fn payment_status_from_str(s: &str) -> PaymentStatus {
    match s {
        "Active"     => PaymentStatus::Active,
        "PastDue"    => PaymentStatus::PastDue,
        "Suspended"  => PaymentStatus::Suspended,
        "Cancelled"  => PaymentStatus::Cancelled,
        "Delinquent" => PaymentStatus::Delinquent,
        _            => PaymentStatus::Trial,
    }
}

fn instance_status_from_str(s: &str) -> InstanceStatus {
    match s {
        "Degraded"    => InstanceStatus::Degraded,
        "GracePeriod" => InstanceStatus::GracePeriod,
        "Suspended"   => InstanceStatus::Suspended,
        "Deactivated" => InstanceStatus::Deactivated,
        _             => InstanceStatus::Active,
    }
}

fn surveillance_event_type_from_str(s: &str) -> SurveillanceEventType {
    match s {
        "UsageReport"      => SurveillanceEventType::UsageReport,
        "PaymentReceived"  => SurveillanceEventType::PaymentReceived,
        "PaymentFailed"    => SurveillanceEventType::PaymentFailed,
        "GracePeriodStart" => SurveillanceEventType::GracePeriodStart,
        "GracePeriodEnd"   => SurveillanceEventType::GracePeriodEnd,
        "DegradeSent"      => SurveillanceEventType::DegradeSent,
        "KillSent"         => SurveillanceEventType::KillSent,
        "Reactivated"      => SurveillanceEventType::Reactivated,
        "TamperDetected"   => SurveillanceEventType::TamperDetected,
        "BinaryMismatch"   => SurveillanceEventType::BinaryMismatch,
        "OverLimitWarning" => SurveillanceEventType::OverLimitWarning,
        "LicenseExpired"   => SurveillanceEventType::LicenseExpired,
        _                  => SurveillanceEventType::Heartbeat,
    }
}
