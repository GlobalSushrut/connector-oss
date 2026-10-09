//! Agent DNS — the `agent://` address space.
//!
//! Provides registration, resolution, and AgentCard serving for the agent mesh.
//! Every agent-to-agent call resolves through here before hitting the mesh proxy.
//!
//! FQAN (Fully Qualified Agent Name) format:
//!   `{name}.{version}.{team}.{org}`  e.g. `summarizer.v2.medical.acme-corp`
//!   `{name}.{version}` (short form, team/org from context)

use anyhow::{Context, Result};
use chrono::Utc;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::time::{Duration, Instant};
use uuid::Uuid;
use validator::Validate;

// reqwest used in health_sweeper
use reqwest::Client as HttpClient;

// ── DNS resolution cache ──────────────────────────────────────────────────────
// Keyed by FQAN → (AgentCard, cached_at)
static DNS_CACHE: Lazy<DashMap<String, (AgentCard, Instant)>> = Lazy::new(DashMap::new);

const DEFAULT_TTL_SECS: u64 = 30;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEndpoint {
    pub id:                   Uuid,
    pub agent_id:             Uuid,
    pub endpoint_url:         String,
    pub region:               Option<String>,
    pub weight:               i32,
    pub health_status:        String,
    pub last_health_at:       Option<chrono::DateTime<Utc>>,
    pub consecutive_failures: i32,
    pub metadata:             Value,
    pub enabled:              bool,
    pub created_at:           chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id:               Uuid,
    pub agent_id:         Uuid,
    pub name:             String,
    pub version_label:    String,
    pub team:             Option<String>,
    pub org:              Option<String>,
    pub fqan:             String,
    pub routing_policy:   String,
    pub canary_weight:    i32,
    pub canary_target_id: Option<Uuid>,
    pub ttl_secs:         i32,
    pub enabled:          bool,
    pub agent_card:       Value,
    pub created_at:       chrono::DateTime<Utc>,
    pub updated_at:       chrono::DateTime<Utc>,
}

/// AgentCard — A2A-compatible capability manifest returned on DNS resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    pub fqan:          String,
    pub name:          String,
    pub version:       String,
    pub team:          Option<String>,
    pub description:   Option<String>,
    pub endpoints:     Vec<ResolvedEndpoint>,
    pub capabilities:  Value,   // MCP tools, input/output schemas
    pub auth:          Value,   // required auth type + scopes
    pub slo:           Option<Value>,
    pub ttl_secs:      i32,
    pub resolved_at:   chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedEndpoint {
    pub url:           String,
    pub region:        Option<String>,
    pub weight:        i32,
    pub health_status: String,
}

// ── Request types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    pub agent_id:      Option<Uuid>,
    #[validate(length(min = 1, max = 128))]
    pub name:          String,
    #[validate(length(max = 64))]
    pub version_label: Option<String>,
    #[validate(length(max = 64))]
    pub team:          Option<String>,
    #[validate(length(max = 128))]
    pub org:           Option<String>,
    #[validate(url)]
    pub endpoint_url:  String,
    #[validate(length(max = 32))]
    pub region:        Option<String>,
    #[validate(range(min = 0, max = 100))]
    pub weight:        Option<i32>,
    pub routing_policy: Option<String>,
    pub capabilities:  Option<Value>,
    pub auth:          Option<Value>,
    #[validate(length(max = 512))]
    pub description:   Option<String>,
}

// ── Registration ──────────────────────────────────────────────────────────────

/// Register an agent endpoint and create/update the DNS record.
/// If agent_id is None, creates a new agent entity first.
pub async fn register(pool: &PgPool, req: RegisterRequest) -> Result<(DnsRecord, AgentEndpoint)> {
    req.validate().map_err(|e| anyhow::anyhow!("Validation: {}", e))?;
    let agent_id = if let Some(id) = req.agent_id {
        // Verify agent exists
        sqlx::query("SELECT id FROM al_agents WHERE id = $1")
            .bind(id).fetch_one(pool).await.context("agent not found")?;
        id
    } else {
        // Auto-create agent entity
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO al_agents (id, name, description, team) VALUES ($1,$2,$3,$4)
             ON CONFLICT DO NOTHING"
        )
        .bind(id).bind(&req.name).bind(req.description.as_deref()).bind(req.team.as_deref())
        .execute(pool).await.context("auto-create agent")?;
        id
    };

    // Create endpoint
    let ep_id = Uuid::new_v4();
    let ep_row = sqlx::query(
        "INSERT INTO al_agent_endpoints (id, agent_id, endpoint_url, region, weight, metadata)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *"
    )
    .bind(ep_id)
    .bind(agent_id)
    .bind(&req.endpoint_url)
    .bind(req.region.as_deref())
    .bind(req.weight.unwrap_or(100))
    .bind(json!({}))
    .fetch_one(pool).await.context("create endpoint")?;

    // Build FQAN
    let version  = req.version_label.as_deref().unwrap_or("latest");
    let fqan     = build_fqan(&req.name, version, req.team.as_deref(), req.org.as_deref());

    // Build AgentCard
    let agent_card = json!({
        "name":        req.name,
        "version":     version,
        "team":        req.team,
        "description": req.description,
        "capabilities": req.capabilities.unwrap_or(json!({})),
        "auth":        req.auth.unwrap_or(json!({"type": "api_key"})),
        "endpoints":   [{ "url": req.endpoint_url, "region": req.region, "weight": req.weight.unwrap_or(100) }],
    });

    // Upsert DNS record
    let dns_row = sqlx::query(
        "INSERT INTO al_dns_records
         (id, agent_id, name, version_label, team, org, fqan, routing_policy, agent_card)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (fqan) DO UPDATE SET
            agent_id       = EXCLUDED.agent_id,
            routing_policy = EXCLUDED.routing_policy,
            agent_card     = EXCLUDED.agent_card,
            updated_at     = NOW()
         RETURNING *"
    )
    .bind(Uuid::new_v4())
    .bind(agent_id)
    .bind(&req.name)
    .bind(version)
    .bind(req.team.as_deref())
    .bind(req.org.as_deref())
    .bind(&fqan)
    .bind(req.routing_policy.as_deref().unwrap_or("round_robin"))
    .bind(&agent_card)
    .fetch_one(pool).await.context("upsert dns record")?;

    DNS_CACHE.remove(&fqan);
    metrics::counter!("agentloop_dns_registrations_total").increment(1);
    tracing::info!(fqan = %fqan, endpoint = %req.endpoint_url, "Agent registered in DNS");

    Ok((row_to_dns(dns_row), row_to_endpoint(ep_row)))
}

// ── Resolution ────────────────────────────────────────────────────────────────

/// Resolve a FQAN to a live AgentCard with healthy endpoints.
/// Returns from TTL cache when fresh; falls through to DB on miss/expiry.
pub async fn resolve(pool: &PgPool, fqan: &str) -> Result<AgentCard> {
    // Cache hit
    if let Some(entry) = DNS_CACHE.get(fqan) {
        let (card, cached_at) = entry.value();
        let ttl = Duration::from_secs(card.ttl_secs.max(1) as u64);
        if cached_at.elapsed() < ttl {
            metrics::counter!("agentloop_dns_cache_hits_total").increment(1);
            return Ok(card.clone());
        }
    }
    metrics::counter!("agentloop_dns_cache_misses_total").increment(1);

    let dns = get_record(pool, fqan).await?;
    if !dns.enabled {
        anyhow::bail!("DNS record {} is disabled", fqan);
    }

    let endpoints = healthy_endpoints(pool, dns.agent_id).await?;
    if endpoints.is_empty() {
        anyhow::bail!("No healthy endpoints for {}", fqan);
    }

    let agent_row = sqlx::query("SELECT name, description, team FROM al_agents WHERE id = $1")
        .bind(dns.agent_id).fetch_optional(pool).await.context("fetch agent")?;

    let (agent_name, agent_desc, agent_team) = agent_row
        .map(|r| (
            r.try_get::<String, _>("name").unwrap_or_default(),
            r.try_get::<Option<String>, _>("description").ok().flatten(),
            r.try_get::<Option<String>, _>("team").ok().flatten(),
        ))
        .unwrap_or_default();

    let resolved_endpoints: Vec<ResolvedEndpoint> = endpoints.iter().map(|ep| ResolvedEndpoint {
        url:           ep.endpoint_url.clone(),
        region:        ep.region.clone(),
        weight:        ep.weight,
        health_status: ep.health_status.clone(),
    }).collect();

    let card = AgentCard {
        fqan:         fqan.to_owned(),
        name:         agent_name,
        version:      dns.version_label.clone(),
        team:         agent_team,
        description:  agent_desc,
        endpoints:    resolved_endpoints,
        capabilities: dns.agent_card.get("capabilities").cloned().unwrap_or(json!({})),
        auth:         dns.agent_card.get("auth").cloned().unwrap_or(json!({"type": "api_key"})),
        slo:          None,
        ttl_secs:     dns.ttl_secs,
        resolved_at:  Utc::now(),
    };

    DNS_CACHE.insert(fqan.to_owned(), (card.clone(), Instant::now()));
    Ok(card)
}

/// Pick the best single endpoint for a call, respecting routing policy and weights.
pub async fn pick_endpoint(pool: &PgPool, fqan: &str) -> Result<AgentEndpoint> {
    let dns       = get_record(pool, fqan).await?;
    let endpoints = healthy_endpoints(pool, dns.agent_id).await?;

    if endpoints.is_empty() {
        anyhow::bail!("No healthy endpoints for {}", fqan);
    }

    // Weighted random selection
    let total: i32 = endpoints.iter().map(|e| e.weight).sum();
    if total == 0 {
        return Ok(endpoints[0].clone());
    }
    let pick = (rand_u32() % total as u32) as i32;
    let mut cumulative = 0;
    for ep in &endpoints {
        cumulative += ep.weight;
        if pick < cumulative {
            return Ok(ep.clone());
        }
    }
    Ok(endpoints[0].clone())
}

/// Update health status for an endpoint after a hop outcome.
pub async fn update_health(
    pool:       &PgPool,
    ep_id:      Uuid,
    success:    bool,
) -> Result<()> {
    let label = if success { "success" } else { "failure" };
    metrics::counter!("agentloop_endpoint_health_updates_total", "result" => label).increment(1);
    if success {
        sqlx::query(
            "UPDATE al_agent_endpoints
             SET health_status = 'healthy', consecutive_failures = 0, last_health_at = NOW(), updated_at = NOW()
             WHERE id = $1"
        ).bind(ep_id).execute(pool).await.context("update health healthy")?;
    } else {
        sqlx::query(
            "UPDATE al_agent_endpoints
             SET consecutive_failures = consecutive_failures + 1,
                 health_status = CASE WHEN consecutive_failures + 1 >= 3 THEN 'unhealthy' ELSE 'degraded' END,
                 last_health_at = NOW(), updated_at = NOW()
             WHERE id = $1"
        ).bind(ep_id).execute(pool).await.context("update health failed")?;
    }
    Ok(())
}

// ── Lookup helpers ────────────────────────────────────────────────────────────

pub async fn get_record(pool: &PgPool, fqan: &str) -> Result<DnsRecord> {
    let row = sqlx::query("SELECT * FROM al_dns_records WHERE fqan = $1 AND enabled = true")
        .bind(fqan).fetch_one(pool).await
        .map_err(|_| anyhow::anyhow!("DNS record not found: {}", fqan))?;
    Ok(row_to_dns(row))
}

pub async fn list_records(
    pool:   &PgPool,
    team:   Option<&str>,
    limit:  i64,
    offset: i64,
) -> Result<Vec<DnsRecord>> {
    let rows = if let Some(t) = team {
        sqlx::query(
            "SELECT * FROM al_dns_records WHERE team = $1 AND enabled = true ORDER BY name, version_label LIMIT $2 OFFSET $3"
        ).bind(t).bind(limit).bind(offset).fetch_all(pool).await
    } else {
        sqlx::query(
            "SELECT * FROM al_dns_records WHERE enabled = true ORDER BY name, version_label LIMIT $1 OFFSET $2"
        ).bind(limit).bind(offset).fetch_all(pool).await
    }.context("list dns records")?;
    Ok(rows.into_iter().map(row_to_dns).collect())
}

pub async fn deregister(pool: &PgPool, fqan: &str) -> Result<()> {
    sqlx::query("UPDATE al_dns_records SET enabled = false, updated_at = NOW() WHERE fqan = $1")
        .bind(fqan).execute(pool).await.context("deregister")?;
    DNS_CACHE.remove(fqan);
    tracing::info!(fqan = %fqan, "Agent deregistered from DNS");
    Ok(())
}

/// Background task: sweep endpoints for health, evict stale cache entries.
/// Spawn once at startup — runs forever, crashing is intentionally non-fatal.
pub async fn health_sweeper(pool: PgPool) {
    let interval = Duration::from_secs(
        std::env::var("DNS_HEALTH_SWEEP_SECS").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(15)
    );
    loop {
        tokio::time::sleep(interval).await;

        // Re-check all endpoints marked degraded/unhealthy via HTTP HEAD
        let rows = sqlx::query(
            "SELECT id, endpoint_url, agent_id FROM al_agent_endpoints
             WHERE enabled = true AND health_status IN ('degraded','unhealthy','unknown')
             LIMIT 100"
        )
        .fetch_all(&pool).await;

        if let Ok(rows) = rows {
            let client = HttpClient::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            for row in rows {
                let ep_id: Uuid  = row.try_get("id").unwrap_or_else(|_| Uuid::new_v4());
                let url: String  = row.try_get("endpoint_url").unwrap_or_default();
                let health_url   = format!("{}/health", url.trim_end_matches('/'));
                let ok = client.get(&health_url).send().await
                    .map(|r| r.status().is_success()).unwrap_or(false);
                let _ = update_health(&pool, ep_id, ok).await;
            }
        }

        // Evict cache entries older than their TTL
        let now = Instant::now();
        DNS_CACHE.retain(|_, (card, cached_at)| {
            now.duration_since(*cached_at) < Duration::from_secs(card.ttl_secs.max(1) as u64)
        });

        metrics::gauge!("agentloop_dns_cache_size").set(DNS_CACHE.len() as f64);
    }
}

pub async fn healthy_endpoints(pool: &PgPool, agent_id: Uuid) -> Result<Vec<AgentEndpoint>> {
    let rows = sqlx::query(
        "SELECT * FROM al_agent_endpoints
         WHERE agent_id = $1 AND enabled = true
           AND health_status IN ('healthy', 'unknown')
         ORDER BY weight DESC"
    )
    .bind(agent_id).fetch_all(pool).await.context("healthy endpoints")?;
    Ok(rows.into_iter().map(row_to_endpoint).collect())
}

// ── FQAN builder ──────────────────────────────────────────────────────────────

pub fn build_fqan(name: &str, version: &str, team: Option<&str>, org: Option<&str>) -> String {
    match (team, org) {
        (Some(t), Some(o)) => format!("{}.{}.{}.{}", name, version, t, o),
        (Some(t), None)    => format!("{}.{}.{}", name, version, t),
        _                  => format!("{}.{}", name, version),
    }
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn row_to_endpoint(row: sqlx::postgres::PgRow) -> AgentEndpoint {
    AgentEndpoint {
        id:                   row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:             row.try_get("agent_id").unwrap_or_else(|_| Uuid::new_v4()),
        endpoint_url:         row.try_get("endpoint_url").unwrap_or_default(),
        region:               row.try_get("region").ok(),
        weight:               row.try_get("weight").unwrap_or(100),
        health_status:        row.try_get("health_status").unwrap_or_else(|_| "unknown".into()),
        last_health_at:       row.try_get("last_health_at").ok(),
        consecutive_failures: row.try_get("consecutive_failures").unwrap_or(0),
        metadata:             row.try_get("metadata").unwrap_or(json!({})),
        enabled:              row.try_get("enabled").unwrap_or(true),
        created_at:           row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_dns(row: sqlx::postgres::PgRow) -> DnsRecord {
    DnsRecord {
        id:               row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:         row.try_get("agent_id").unwrap_or_else(|_| Uuid::new_v4()),
        name:             row.try_get("name").unwrap_or_default(),
        version_label:    row.try_get("version_label").unwrap_or_else(|_| "latest".into()),
        team:             row.try_get("team").ok(),
        org:              row.try_get("org").ok(),
        fqan:             row.try_get("fqan").unwrap_or_default(),
        routing_policy:   row.try_get("routing_policy").unwrap_or_else(|_| "round_robin".into()),
        canary_weight:    row.try_get("canary_weight").unwrap_or(0),
        canary_target_id: row.try_get("canary_target_id").ok(),
        ttl_secs:         row.try_get("ttl_secs").unwrap_or(30),
        enabled:          row.try_get("enabled").unwrap_or(true),
        agent_card:       row.try_get("agent_card").unwrap_or(json!({})),
        created_at:       row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:       row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

fn rand_u32() -> u32 {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    seed.wrapping_mul(1664525).wrapping_add(1013904223)
}
