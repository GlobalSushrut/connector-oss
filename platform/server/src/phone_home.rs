use crate::binary_id::BinaryIdentity;
use crate::state::SharedState;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Phone-home background task.
/// Runs on startup and periodically to report to the license/surveillance server.
/// Enforces payment compliance — if the server says "shutdown" or "degrade",
/// the binary obeys.

pub static DEGRADED: AtomicBool = AtomicBool::new(false);
pub static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct PhoneHomeConfig {
    pub identity: BinaryIdentity,
    pub checkin_interval_secs: u64,
    pub heartbeat_interval_secs: u64,
}

impl PhoneHomeConfig {
    pub fn from_identity(identity: BinaryIdentity) -> Self {
        Self {
            identity,
            checkin_interval_secs: 3600,   // 1 hour default
            heartbeat_interval_secs: 3600, // 1 hour default
        }
    }
}

/// Startup check-in — called once when binary starts.
/// Returns (allowed, command, banner, permissions).
pub async fn startup_checkin(config: &PhoneHomeConfig) -> (bool, String, String, Vec<String>) {
    if !config.identity.needs_phone_home() {
        return (true, "continue".into(), config.identity.permission_banner.clone(), vec!["basic".into()]);
    }

    let url = format!("{}/rpc/v1/checkin", config.identity.license_server_url);
    let payload = config.identity.to_checkin_payload();

    match http_post(&url, &payload).await {
        Ok(resp) => {
            let allowed = resp.get("allowed").and_then(|v| v.as_bool()).unwrap_or(true);
            let command = resp.get("command").and_then(|v| v.as_str()).unwrap_or("continue").to_string();
            let banner = resp.get("banner").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let permissions: Vec<String> = resp.get("permissions")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            // Update interval from server
            let _next = resp.get("next_checkin_secs").and_then(|v| v.as_u64()).unwrap_or(3600);

            if command == "shutdown" {
                SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
            } else if command == "degrade" {
                DEGRADED.store(true, Ordering::SeqCst);
            }

            (allowed, command, banner, permissions)
        }
        Err(e) => {
            tracing::warn!("License check-in failed: {} — continuing in offline mode", e);
            // Grace: allow startup if server unreachable (offline/air-gapped)
            (true, "offline".into(), config.identity.permission_banner.clone(), vec!["basic".into()])
        }
    }
}

/// Background heartbeat loop — spawned as a tokio task.
/// Periodically reports usage to the surveillance server.
pub fn spawn_heartbeat_loop(state: SharedState, config: PhoneHomeConfig) {
    if !config.identity.needs_phone_home() {
        tracing::info!("Phone-home disabled (no license configured)");
        return;
    }

    tokio::spawn(async move {
        let mut interval_secs = config.heartbeat_interval_secs;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                tracing::error!("Shutdown requested by license server — halting heartbeat");
                break;
            }

            // Gather current metrics
            let (agents, packets, trust, tokens, cost) = {
                let k = state.kernel.lock().unwrap();
                let agent_count = k.agents().len();
                let packet_count = k.packet_count();
                let mut total_tokens: u64 = 0;
                let mut total_cost: f64 = 0.0;
                for (_, acb) in k.agents() {
                    total_tokens += acb.total_tokens_consumed;
                    total_cost += acb.total_cost_usd;
                }
                let trust_score = {
                    let ts = state.trust_score();
                    ts.score
                };
                (agent_count, packet_count, trust_score as u32, total_tokens, total_cost)
            };

            let url = format!("{}/rpc/v1/heartbeat", config.identity.license_server_url);
            let payload = config.identity.to_heartbeat_payload(agents, packets, trust, tokens, cost);

            match http_post(&url, &payload).await {
                Ok(resp) => {
                    let command = resp.get("command").and_then(|v| v.as_str()).unwrap_or("continue");

                    match command {
                        "shutdown" => {
                            tracing::error!("License server issued SHUTDOWN command");
                            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
                            break;
                        }
                        "degrade" => {
                            tracing::warn!("License server issued DEGRADE command — features limited");
                            DEGRADED.store(true, Ordering::SeqCst);
                            // Faster heartbeat when degraded
                            interval_secs = resp.get("next_heartbeat_secs")
                                .and_then(|v| v.as_u64()).unwrap_or(600);
                        }
                        _ => {
                            DEGRADED.store(false, Ordering::SeqCst);
                            interval_secs = resp.get("next_heartbeat_secs")
                                .and_then(|v| v.as_u64()).unwrap_or(3600);
                        }
                    }

                    // Log warnings
                    if let Some(warnings) = resp.get("warnings").and_then(|v| v.as_array()) {
                        for w in warnings {
                            if let Some(msg) = w.as_str() {
                                tracing::warn!("License warning: {}", msg);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Heartbeat failed: {} — will retry in {}s", e, interval_secs);
                }
            }
        }
    });
}

/// Periodic usage report — sends detailed usage to surveillance server.
/// Always-on for all tiers for accurate billing and usage tracking.
pub fn spawn_usage_reporter(state: SharedState, config: PhoneHomeConfig) {
    // Always report usage - required for billing accuracy and quota enforcement
    
    tokio::spawn(async move {
        loop {
            // Report every 6 hours
            tokio::time::sleep(tokio::time::Duration::from_secs(21600)).await;

            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            let (agents, packets, audit_entries, tokens, cost) = {
                let k = state.kernel.lock().unwrap();
                let mut total_tokens: u64 = 0;
                let mut total_cost: f64 = 0.0;
                for (_, acb) in k.agents() {
                    total_tokens += acb.total_tokens_consumed;
                    total_cost += acb.total_cost_usd;
                }
                (k.agents().len(), k.packet_count(), k.audit_log().len(), total_tokens, total_cost)
            };

            let url = format!("{}/rpc/v1/usage", config.identity.license_server_url);
            let payload = serde_json::json!({
                "instance_id": &config.identity.instance_id,
                "agents": agents,
                "packets": packets,
                "audit_entries": audit_entries,
                "total_tokens": tokens,
                "total_cost_usd": cost,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            match http_post(&url, &payload).await {
                Ok(_) => tracing::debug!("Usage report sent"),
                Err(e) => tracing::warn!("Usage report failed: {}", e),
            }
        }
    });
}

/// Check if the binary is in degraded mode (payment issue)
pub fn is_degraded() -> bool {
    DEGRADED.load(Ordering::SeqCst)
}

/// Check if shutdown was requested by the license server
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Simple HTTP POST helper using tokio's TCP + manual HTTP/1.1
/// No external HTTP client dependency needed.
async fn http_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    // Parse URL
    let url_str = url.to_string();
    let is_https = url_str.starts_with("https://");
    let without_scheme = url_str
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let (host_port, path) = match without_scheme.find('/') {
        Some(i) => (&without_scheme[..i], &without_scheme[i..]),
        None => (without_scheme, "/"),
    };
    let (host, port) = match host_port.find(':') {
        Some(i) => (&host_port[..i], host_port[i+1..].parse::<u16>().unwrap_or(if is_https { 443 } else { 80 })),
        None => (host_port, if is_https { 443 } else { 80 }),
    };

    let body_str = serde_json::to_string(body).map_err(|e| e.to_string())?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, body_str.len(), body_str
    );

    // Connect
    let addr = format!("{}:{}", host, port);
    let stream = tokio::net::TcpStream::connect(&addr).await
        .map_err(|e| format!("Connect to {} failed: {}", addr, e))?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.map_err(|e| e.to_string())?;

    let response_str = String::from_utf8_lossy(&response);

    // Parse HTTP response — find body after \r\n\r\n
    let body_start = response_str.find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let response_body = &response_str[body_start..];

    serde_json::from_str(response_body)
        .map_err(|e| format!("Parse response failed: {} (body: {})", e, &response_body[..response_body.len().min(200)]))
}
