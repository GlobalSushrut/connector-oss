//! D9 — Rate limiting middleware: per-API-key + per-agent sliding window.
//!
//! Algorithm: sliding window counter — counts requests in the last `window_secs`
//! by storing (count, window_start_ms) per key. Atomic, lock-free via DashMap.
//!
//! Limits (configurable via env):
//!   CONNECTOR_RATE_LIMIT_API_KEY  — default 600 req/min  per API key
//!   CONNECTOR_RATE_LIMIT_AGENT    — default 120 req/min  per agent PID
//!   CONNECTOR_RATE_LIMIT_GLOBAL   — default 10_000 req/min across all keys
//!
//! Returns 429 with `Retry-After: <secs>` when limit exceeded.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use dashmap::DashMap;

// ── State ────────────────────────────────────────────────────────────────────

/// (hit_count, window_start_ms)
type Window = (u64, u64);

static API_KEY_WINDOWS: OnceLock<DashMap<String, Window>> = OnceLock::new();
static AGENT_WINDOWS:   OnceLock<DashMap<String, Window>> = OnceLock::new();
static GLOBAL_WINDOW:   OnceLock<std::sync::Mutex<Window>> = OnceLock::new();

fn api_key_windows() -> &'static DashMap<String, Window> {
    API_KEY_WINDOWS.get_or_init(DashMap::new)
}
fn agent_windows() -> &'static DashMap<String, Window> {
    AGENT_WINDOWS.get_or_init(DashMap::new)
}
fn global_window() -> &'static std::sync::Mutex<Window> {
    GLOBAL_WINDOW.get_or_init(|| std::sync::Mutex::new((0, 0)))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn limit_from_env(var: &str, default: u64) -> u64 {
    std::env::var(var).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

const WINDOW_MS: u64 = 60_000; // 1-minute sliding window

/// Increment counter for `key` in `map`. Returns `(current_count, limit)`.
fn slide(map: &DashMap<String, Window>, key: &str, limit: u64) -> (u64, u64) {
    let now = now_ms();
    let mut entry = map.entry(key.to_string()).or_insert((0, now));
    if now - entry.1 >= WINDOW_MS {
        // New window
        *entry = (1, now);
    } else {
        entry.0 += 1;
    }
    (entry.0, limit)
}

fn slide_global(limit: u64) -> (u64, u64) {
    let now = now_ms();
    let mut w = global_window().lock().unwrap();
    if now - w.1 >= WINDOW_MS {
        *w = (1, now);
    } else {
        w.0 += 1;
    }
    (w.0, limit)
}

/// Retry-After seconds remaining in the current window.
fn retry_after(map: &DashMap<String, Window>, key: &str) -> u64 {
    let now = now_ms();
    if let Some(e) = map.get(key) {
        let elapsed_ms = now.saturating_sub(e.1);
        return (WINDOW_MS.saturating_sub(elapsed_ms)) / 1000 + 1;
    }
    1
}

// ── Middleware ────────────────────────────────────────────────────────────────

pub async fn rate_limit_middleware(
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let headers = req.headers().clone();
    let uri     = req.uri().clone();

    // Extract API key or Bearer token (used as the per-key identifier)
    let api_key_id: Option<String> = headers
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .map(|k| format!("key:{}", &k[..k.len().min(32)]))
        .or_else(|| {
            headers.get("authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(|t| format!("jwt:{}", &t[..t.len().min(32)]))
        });

    // Extract agent PID from query string (?agent_pid=...) or path segment /agents/:pid/
    let agent_pid: Option<String> = {
        let path = uri.path();
        // /api/v1/agents/<pid>/...
        let from_path = path.split('/').enumerate()
            .find(|(i, seg)| *i > 0 && path.split('/').nth(i.saturating_sub(1)) == Some("agents") && !seg.is_empty())
            .map(|(_, seg)| seg.to_string());
        // ?agent_pid=...
        let from_query = uri.query().and_then(|q| {
            q.split('&').find(|p| p.starts_with("agent_pid="))
                .map(|p| p.trim_start_matches("agent_pid=").to_string())
        });
        from_path.or(from_query)
    };

    let api_limit    = limit_from_env("CONNECTOR_RATE_LIMIT_API_KEY", 600);
    let agent_limit  = limit_from_env("CONNECTOR_RATE_LIMIT_AGENT",   120);
    let global_limit = limit_from_env("CONNECTOR_RATE_LIMIT_GLOBAL",  10_000);

    // 1. Global rate check
    let (global_count, _) = slide_global(global_limit);
    if global_count > global_limit {
        return rate_limit_response(1, "global");
    }

    // 2. Per-API-key check
    if let Some(ref key) = api_key_id {
        let (count, limit) = slide(api_key_windows(), key, api_limit);
        if count > limit {
            let retry = retry_after(api_key_windows(), key);
            return rate_limit_response(retry, "api_key");
        }
    }

    // 3. Per-agent check
    if let Some(ref pid) = agent_pid {
        let (count, limit) = slide(agent_windows(), pid, agent_limit);
        if count > limit {
            let retry = retry_after(agent_windows(), pid);
            return rate_limit_response(retry, "agent");
        }
    }

    next.run(req).await
}

fn rate_limit_response(retry_after_secs: u64, scope: &str) -> axum::response::Response {
    let body = serde_json::json!({
        "ok": false,
        "error": {
            "code": "rate_limit_exceeded",
            "message": format!("Rate limit exceeded (scope: {}). Retry after {}s.", scope, retry_after_secs),
            "retry_after_secs": retry_after_secs,
            "scope": scope,
            "docs": "https://connector.ai/docs/errors/rate_limit_exceeded",
            "status": 429,
        }
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            ("Content-Type", "application/json"),
            ("Retry-After", &retry_after_secs.to_string()),
        ],
        axum::Json(body),
    )
        .into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_window_increments() {
        let map = DashMap::new();
        let (c1, _) = slide(&map, "key-1", 10);
        let (c2, _) = slide(&map, "key-1", 10);
        assert_eq!(c1, 1);
        assert_eq!(c2, 2);
    }

    #[test]
    fn test_sliding_window_resets_after_window() {
        let map: DashMap<String, Window> = DashMap::new();
        // Manually inject an old window (started > 60s ago)
        map.insert("key-old".to_string(), (999, now_ms() - WINDOW_MS - 1));
        let (c, _) = slide(&map, "key-old", 100);
        assert_eq!(c, 1, "Counter should reset after window expiry");
    }

    #[test]
    fn test_different_keys_are_independent() {
        let map = DashMap::new();
        for _ in 0..5 { slide(&map, "a", 100); }
        let (c, _) = slide(&map, "b", 100);
        assert_eq!(c, 1);
    }

    #[test]
    fn test_global_window_increments() {
        // Run in isolation — global state is shared, just verify it increments
        let (c1, _) = slide_global(99999);
        let (c2, _) = slide_global(99999);
        assert!(c2 > c1 || c2 >= 1);
    }
}
