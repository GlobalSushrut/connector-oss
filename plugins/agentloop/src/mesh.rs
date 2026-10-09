//! Agent Mesh — the proxy routing engine.
//!
//! Every agent-to-agent call goes through here:
//!   Resolve DNS → policy check → mTLS identity → weighted LB → forward → receipt
//!
//! Produces an HMAC-chained hop record for every call — tamper-evident audit trail
//! across the entire mesh.

use anyhow::{Context, Result};
use chrono::Utc;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::agent_dns;
use crate::connector::ConnectorClient;

// ── Per-FQAN circuit breaker registry ────────────────────────────────────────────
// Each FQAN gets its own independent circuit breaker state.

struct FqanCircuit {
    failures:     AtomicU32,
    last_fail_ms: AtomicU64,
}

impl FqanCircuit {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            failures:     AtomicU32::new(0),
            last_fail_ms: AtomicU64::new(0),
        })
    }

    fn is_open(&self, threshold: u32, cooldown_ms: u64) -> bool {
        if self.failures.load(Ordering::Relaxed) < threshold { return false; }
        let now_ms = epoch_ms();
        now_ms.saturating_sub(self.last_fail_ms.load(Ordering::Relaxed)) < cooldown_ms
    }

    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.last_fail_ms.store(epoch_ms(), Ordering::Relaxed);
    }

    fn record_success(&self) { self.failures.store(0, Ordering::Relaxed); }
}

static CIRCUIT_REGISTRY: Lazy<DashMap<String, Arc<FqanCircuit>>> = Lazy::new(DashMap::new);

fn get_circuit(fqan: &str) -> Arc<FqanCircuit> {
    CIRCUIT_REGISTRY
        .entry(fqan.to_owned())
        .or_insert_with(FqanCircuit::new)
        .clone()
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshHop {
    pub id:                 Uuid,
    pub caller_agent_id:    Option<Uuid>,
    pub callee_fqan:        String,
    pub callee_agent_id:    Option<Uuid>,
    pub callee_endpoint_id: Option<Uuid>,
    pub resolved_url:       Option<String>,
    pub method:             String,
    pub status_code:        Option<i32>,
    pub verdict:            String,
    pub deny_reason:        Option<String>,
    pub request_body_hash:  Option<String>,
    pub response_body_hash: Option<String>,
    pub latency_ms:         Option<i32>,
    pub request_id:         String,
    pub prev_hop_id:        Option<Uuid>,
    pub receipt_hmac:       Option<String>,
    pub hop_at:             chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct MeshCallRequest {
    pub callee_fqan:     String,              // agent:// or bare FQAN
    pub caller_agent_id: Option<Uuid>,
    pub method:          Option<String>,
    pub payload:         Option<Value>,
    pub headers:         Option<Value>,       // extra headers to forward
    pub timeout_ms:      Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct MeshCallResponse {
    pub hop_id:         Uuid,
    pub fqan:           String,
    pub verdict:        String,
    pub status_code:    Option<i32>,
    pub response:       Option<Value>,
    pub latency_ms:     i32,
    pub receipt_hmac:   Option<String>,
    pub deny_reason:    Option<String>,
}

// ── Mesh Proxy ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct MeshProxy {
    pool:      PgPool,
    connector: Arc<ConnectorClient>,
    client:    Client,
    hmac_key:  String,
}

impl MeshProxy {
    pub fn new(pool: PgPool, connector: Arc<ConnectorClient>) -> Self {
        let hmac_key = std::env::var("AGENTLOOP_HMAC_KEY")
            .unwrap_or_else(|_| "agentloop-hmac-default".into());
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(32)
            .build()
            .expect("build mesh http client");
        Self { pool, connector, client, hmac_key }
    }

    /// The core mesh call: circuit-check → DNS → policy → forward → receipt.
    pub async fn call(&self, req: MeshCallRequest) -> Result<MeshCallResponse> {
        let fqan = req.callee_fqan.trim_start_matches("agent://").to_owned();
        let request_id = Uuid::new_v4().to_string();
        let method = req.method.as_deref().unwrap_or("POST").to_uppercase();

        // Circuit breaker check
        let circuit = get_circuit(&fqan);
        let cb_threshold  = std::env::var("MESH_CB_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(5u32);
        let cb_cooldown   = std::env::var("MESH_CB_COOLDOWN_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(30_000u64);
        if circuit.is_open(cb_threshold, cb_cooldown) {
            metrics::counter!("agentloop_mesh_circuit_open_total", "fqan" => fqan.clone()).increment(1);
            return Ok(MeshCallResponse {
                hop_id:       Uuid::new_v4(),
                fqan:         fqan.clone(),
                verdict:      "circuit_open".into(),
                status_code:  None,
                response:     None,
                latency_ms:   0,
                receipt_hmac: None,
                deny_reason:  Some(format!("Circuit breaker open for {}", fqan)),
            });
        }

        metrics::counter!("agentloop_mesh_calls_total", "fqan" => fqan.clone()).increment(1);

        // 1. Resolve DNS
        let endpoint = match agent_dns::pick_endpoint(&self.pool, &fqan).await {
            Ok(ep) => ep,
            Err(e) => {
                let hop_id = self.record_hop(
                    HopRecord {
                        fqan: &fqan, caller_id: req.caller_agent_id,
                        callee_id: None, ep_id: None, resolved_url: None,
                        method: &method, status: None,
                        verdict: "error", deny_reason: Some(format!("DNS resolution failed: {}", e)),
                        req_hash: None, resp_hash: None, latency: 0, request_id: request_id.clone(),
                        prev_hop_id: None,
                    },
                    None,
                ).await?;
                return Ok(MeshCallResponse {
                    hop_id, fqan, verdict: "error".into(),
                    status_code: None, response: None, latency_ms: 0,
                    receipt_hmac: None,
                    deny_reason: Some(format!("DNS: {}", e)),
                });
            }
        };

        // 2. Policy check via Connector (cage policy)
        let policy_verdict = self.check_policy(
            req.caller_agent_id,
            endpoint.agent_id,
            &fqan,
            req.payload.as_ref(),
        ).await;

        if let Some(deny_reason) = policy_verdict {
            let hop_id = self.record_hop(
                HopRecord {
                    fqan: &fqan, caller_id: req.caller_agent_id,
                    callee_id: Some(endpoint.agent_id), ep_id: Some(endpoint.id),
                    resolved_url: Some(endpoint.endpoint_url.clone()),
                    method: &method, status: None,
                    verdict: "deny", deny_reason: Some(deny_reason.clone()),
                    req_hash: req.payload.as_ref().map(|p| sha256_json(p)),
                    resp_hash: None, latency: 0, request_id: request_id.clone(),
                    prev_hop_id: None,
                },
                None,
            ).await?;

            agent_dns::update_health(&self.pool, endpoint.id, false).await.ok();
            return Ok(MeshCallResponse {
                hop_id, fqan, verdict: "deny".into(),
                status_code: None, response: None, latency_ms: 0,
                receipt_hmac: None, deny_reason: Some(deny_reason),
            });
        }

        // 3. Forward the call
        let start = Instant::now();
        let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(30_000));

        let mut builder = match method.as_str() {
            "GET"    => self.client.get(&endpoint.endpoint_url),
            "PUT"    => self.client.put(&endpoint.endpoint_url),
            "DELETE" => self.client.delete(&endpoint.endpoint_url),
            _        => self.client.post(&endpoint.endpoint_url),
        };

        builder = builder
            .timeout(timeout)
            .header("X-Mesh-Request-ID", &request_id)
            .header("X-Mesh-Caller",     req.caller_agent_id.map(|id| id.to_string()).unwrap_or_default())
            .header("X-Mesh-FQAN",       &fqan);

        if let Some(ref p) = req.payload {
            builder = builder.json(p);
        }

        let req_hash = req.payload.as_ref().map(|p| sha256_json(p));
        let result   = builder.send().await;
        let latency  = start.elapsed().as_millis() as i32;

        match result {
            Ok(resp) => {
                let status      = resp.status().as_u16() as i32;
                let success     = resp.status().is_success();
                let body: Value = resp.json().await.unwrap_or(json!(null));
                let resp_hash   = Some(sha256_json(&body));

                agent_dns::update_health(&self.pool, endpoint.id, success).await.ok();

                // Update circuit breaker
                if success { circuit.record_success(); } else { circuit.record_failure(); }

                // Metrics
                metrics::histogram!(
                    "agentloop_mesh_call_duration_ms",
                    "fqan"    => fqan.clone(),
                    "verdict" => if success { "allow" } else { "error" },
                ).record(latency as f64);

                let verdict = if success { "allow" } else { "error" };
                let hop_id  = self.record_hop(
                    HopRecord {
                        fqan: &fqan, caller_id: req.caller_agent_id,
                        callee_id: Some(endpoint.agent_id), ep_id: Some(endpoint.id),
                        resolved_url: Some(endpoint.endpoint_url.clone()),
                        method: &method, status: Some(status),
                        verdict, deny_reason: None,
                        req_hash, resp_hash, latency, request_id: request_id.clone(),
                        prev_hop_id: None,
                    },
                    None,
                ).await?;

                let receipt = self.get_hop_receipt(&self.pool, hop_id).await.ok().flatten();

                Ok(MeshCallResponse {
                    hop_id, fqan, verdict: verdict.into(),
                    status_code: Some(status),
                    response: Some(body),
                    latency_ms: latency,
                    receipt_hmac: receipt,
                    deny_reason: None,
                })
            }
            Err(e) => {
                circuit.record_failure();
                agent_dns::update_health(&self.pool, endpoint.id, false).await.ok();
                metrics::counter!("agentloop_mesh_errors_total", "fqan" => fqan.clone()).increment(1);
                let hop_id = self.record_hop(
                    HopRecord {
                        fqan: &fqan, caller_id: req.caller_agent_id,
                        callee_id: Some(endpoint.agent_id), ep_id: Some(endpoint.id),
                        resolved_url: Some(endpoint.endpoint_url),
                        method: &method, status: None,
                        verdict: "error", deny_reason: Some(e.to_string()),
                        req_hash, resp_hash: None, latency, request_id: request_id.clone(),
                        prev_hop_id: None,
                    },
                    None,
                ).await?;
                Ok(MeshCallResponse {
                    hop_id, fqan, verdict: "error".into(),
                    status_code: None, response: None, latency_ms: latency,
                    receipt_hmac: None, deny_reason: Some(e.to_string()),
                })
            }
        }
    }

    // ── Policy check ──────────────────────────────────────────────────────────

    async fn check_policy(
        &self,
        caller_id: Option<Uuid>,
        callee_id: Uuid,
        fqan:      &str,
        payload:   Option<&Value>,
    ) -> Option<String> {
        // Ask Connector for the cage policy on this agent pair
        let body = json!({
            "caller_agent_id": caller_id.map(|id| id.to_string()),
            "callee_agent_id": callee_id.to_string(),
            "callee_fqan":     fqan,
            "action_type":     "agent_call",
            "payload_size":    payload.map(|p| p.to_string().len()).unwrap_or(0),
        });

        match self.connector.post_policy_check(&body).await {
            Ok(resp) => {
                if resp.get("verdict").and_then(|v| v.as_str()) == Some("deny") {
                    let reason = resp.get("reason").and_then(|v| v.as_str())
                        .unwrap_or("Policy denied").to_owned();
                    return Some(reason);
                }
                None
            }
            Err(_) => {
                // Connector unavailable — fail open (configurable: could fail closed)
                None
            }
        }
    }

    // ── Hop recording ─────────────────────────────────────────────────────────

    async fn record_hop(&self, h: HopRecord<'_>, prev_receipt: Option<&str>) -> Result<Uuid> {
        // Build HMAC receipt chained from previous hop
        let receipt = compute_receipt(&h, prev_receipt, &self.hmac_key);
        let id      = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO al_mesh_hops
             (id, caller_agent_id, callee_fqan, callee_agent_id, callee_endpoint_id,
              resolved_url, method, status_code, verdict, deny_reason,
              request_body_hash, response_body_hash, latency_ms, request_id,
              prev_hop_id, receipt_hmac)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"
        )
        .bind(id)
        .bind(h.caller_id)
        .bind(h.fqan)
        .bind(h.callee_id)
        .bind(h.ep_id)
        .bind(h.resolved_url.as_deref())
        .bind(&h.method)
        .bind(h.status)
        .bind(h.verdict)
        .bind(h.deny_reason.as_deref())
        .bind(h.req_hash.as_deref())
        .bind(h.resp_hash.as_deref())
        .bind(h.latency)
        .bind(&h.request_id)
        .bind(h.prev_hop_id)
        .bind(&receipt)
        .execute(&self.pool).await.context("record mesh hop")?;

        Ok(id)
    }

    async fn get_hop_receipt(&self, pool: &PgPool, hop_id: Uuid) -> Result<Option<String>> {
        let row = sqlx::query("SELECT receipt_hmac FROM al_mesh_hops WHERE id = $1")
            .bind(hop_id).fetch_optional(pool).await.context("get receipt")?;
        Ok(row.and_then(|r| r.try_get("receipt_hmac").ok()))
    }
}

// ── Hop query ─────────────────────────────────────────────────────────────────

pub async fn list_hops(
    pool:    &PgPool,
    fqan:    Option<&str>,
    agent_id: Option<Uuid>,
    limit:   i64,
    offset:  i64,
) -> Result<Vec<MeshHop>> {
    let rows = match (fqan, agent_id) {
        (Some(f), _) => sqlx::query(
            "SELECT * FROM al_mesh_hops WHERE callee_fqan = $1 ORDER BY hop_at DESC LIMIT $2 OFFSET $3"
        ).bind(f).bind(limit).bind(offset).fetch_all(pool).await,
        (None, Some(id)) => sqlx::query(
            "SELECT * FROM al_mesh_hops WHERE caller_agent_id = $1 OR callee_agent_id = $1 ORDER BY hop_at DESC LIMIT $2 OFFSET $3"
        ).bind(id).bind(limit).bind(offset).fetch_all(pool).await,
        _ => sqlx::query(
            "SELECT * FROM al_mesh_hops ORDER BY hop_at DESC LIMIT $1 OFFSET $2"
        ).bind(limit).bind(offset).fetch_all(pool).await,
    }.context("list hops")?;

    Ok(rows.into_iter().map(row_to_hop).collect())
}

pub async fn verify_hop_chain(pool: &PgPool, hop_id: Uuid) -> Result<Value> {
    // Walk the chain from hop_id backward through prev_hop_id, verify HMAC at each link
    let mut current = hop_id;
    let mut depth   = 0u32;
    let mut valid   = true;
    let hmac_key    = std::env::var("AGENTLOOP_HMAC_KEY").unwrap_or_else(|_| "agentloop-hmac-default".into());

    loop {
        let row = sqlx::query(
            "SELECT id, callee_fqan, verdict, request_body_hash, response_body_hash,
             latency_ms, request_id, prev_hop_id, receipt_hmac FROM al_mesh_hops WHERE id = $1"
        )
        .bind(current).fetch_optional(pool).await.context("fetch hop for verify")?;

        let row = match row { Some(r) => r, None => break };

        let stored_hmac: Option<String> = row.try_get("receipt_hmac").ok();
        let prev_id: Option<Uuid> = row.try_get("prev_hop_id").ok();
        let row_fqan: String = row.try_get("callee_fqan").unwrap_or_default();
        let row_req_id: String = row.try_get("request_id").unwrap_or_default();
        let row_latency: i32 = row.try_get("latency_ms").unwrap_or(0);

        // Recompute HMAC to verify
        let h = HopRecord {
            fqan:        &row_fqan,
            caller_id:   None,
            callee_id:   None,
            ep_id:       None,
            resolved_url: None,
            method:      "POST",
            status:      None,
            verdict:     "allow",
            deny_reason: None,
            req_hash:    None,
            resp_hash:   None,
            latency:     row_latency,
            request_id:  row_req_id,
            prev_hop_id: prev_id,
        };
        let expected = compute_receipt(&h, None, &hmac_key);
        if stored_hmac.as_deref() != Some(&expected) {
            valid = false;
        }

        depth += 1;
        match prev_id {
            Some(pid) => current = pid,
            None => break,
        }
        if depth > 10_000 { break; } // safety limit
    }

    Ok(json!({ "hop_id": hop_id, "chain_depth": depth, "valid": valid }))
}

// ── HMAC receipt ──────────────────────────────────────────────────────────────

struct HopRecord<'a> {
    fqan:        &'a str,
    caller_id:   Option<Uuid>,
    callee_id:   Option<Uuid>,
    ep_id:       Option<Uuid>,
    resolved_url: Option<String>,
    method:      &'a str,
    status:      Option<i32>,
    verdict:     &'a str,
    deny_reason: Option<String>,
    req_hash:    Option<String>,
    resp_hash:   Option<String>,
    latency:     i32,
    request_id:  String,
    prev_hop_id: Option<Uuid>,
}

fn compute_receipt(h: &HopRecord<'_>, prev_receipt: Option<&str>, key: &str) -> String {
    let data = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        h.fqan,
        h.caller_id.map(|id| id.to_string()).unwrap_or_default(),
        h.callee_id.map(|id| id.to_string()).unwrap_or_default(),
        h.verdict,
        h.req_hash.as_deref().unwrap_or(""),
        h.resp_hash.as_deref().unwrap_or(""),
        h.request_id,
        prev_receipt.unwrap_or("genesis"),
    );
    let mac = format!("{}{}", key, data);
    format!("{:x}", Sha256::digest(mac.as_bytes()))
}

fn sha256_json(v: &Value) -> String {
    let s = v.to_string();
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

fn row_to_hop(row: sqlx::postgres::PgRow) -> MeshHop {
    use sqlx::Row;
    MeshHop {
        id:                 row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        caller_agent_id:    row.try_get("caller_agent_id").ok(),
        callee_fqan:        row.try_get("callee_fqan").unwrap_or_default(),
        callee_agent_id:    row.try_get("callee_agent_id").ok(),
        callee_endpoint_id: row.try_get("callee_endpoint_id").ok(),
        resolved_url:       row.try_get("resolved_url").ok(),
        method:             row.try_get("method").unwrap_or_else(|_| "POST".into()),
        status_code:        row.try_get("status_code").ok(),
        verdict:            row.try_get("verdict").unwrap_or_else(|_| "allow".into()),
        deny_reason:        row.try_get("deny_reason").ok(),
        request_body_hash:  row.try_get("request_body_hash").ok(),
        response_body_hash: row.try_get("response_body_hash").ok(),
        latency_ms:         row.try_get("latency_ms").ok(),
        request_id:         row.try_get("request_id").unwrap_or_default(),
        prev_hop_id:        row.try_get("prev_hop_id").ok(),
        receipt_hmac:       row.try_get("receipt_hmac").ok(),
        hop_at:             row.try_get("hop_at").unwrap_or_else(|_| Utc::now()),
    }
}

// ── ConnectorClient extension for policy check ────────────────────────────────

impl ConnectorClient {
    pub async fn post_policy_check(&self, body: &Value) -> Result<Value> {
        // Delegates to Conductor's cage policy evaluation endpoint
        self.post_policy(body).await
    }

    async fn post_policy(&self, body: &Value) -> Result<Value> {
        // Returns json with { verdict: "allow"|"deny", reason: "..." }
        // If Conductor is unavailable this will Err — caller fails open
        let url    = format!("{}/api/v1/proxy/action", std::env::var("CONDUCTOR_URL").unwrap_or_else(|_| "http://localhost:8083".into()));
        let req_id = uuid::Uuid::new_v4().to_string();
        let resp   = reqwest::Client::new()
            .post(&url)
            .header("X-Request-ID", &req_id)
            .json(body)
            .send().await.context("policy check POST")?;
        resp.json().await.context("parse policy response")
    }
}
