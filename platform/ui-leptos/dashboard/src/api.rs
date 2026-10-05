use gloo_net::http::Request;
use gloo_storage::{LocalStorage, Storage};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub const BASE: &str = "/api/v1";

/// Resolve a dashboard path to a full API URL.
/// Paths that already start with `/api/` (v1 or v2) are used as-is.
fn api_url(path: &str) -> String {
    if path.starts_with("/api/") {
        path.to_string()
    } else {
        format!("{BASE}{path}")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiError {
    pub status: u16,
    pub code: Option<String>,
    pub message: String,
    pub detail: Option<String>,
    pub hints: Vec<String>,
    pub docs: Option<String>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API {} — {}", self.status, self.message)?;
        if let Some(d) = &self.detail {
            if !d.is_empty() && d != &self.message {
                write!(f, " ({d})")?;
            }
        } else if !self.hints.is_empty() {
            write!(f, " (hint: {})", self.hints.join("; "))?;
        }
        Ok(())
    }
}

fn is_canonical_result(value: &Value) -> bool {
    value.get("ok").and_then(|v| v.as_bool()).is_some()
        && value.get("intent").and_then(|v| v.as_object()).is_some()
        && value.get("data").is_some()
}

fn singularize(value: &str) -> String {
    value.strip_suffix('s').unwrap_or(value).to_string()
}

fn infer_intent(method: &str, path: &str) -> (String, String, String) {
    let bare = path.split('?').next().unwrap_or(path);
    let parts: Vec<&str> = bare
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let first = parts.first().copied().unwrap_or("resource");
    let last = parts.last().copied().unwrap_or(first);
    match (method, parts.as_slice()) {
        ("GET", [noun]) => ("list".to_string(), singularize(noun), "all".to_string()),
        ("GET", [noun, target]) => ("show".to_string(), singularize(noun), (*target).to_string()),
        ("POST", [noun, target, action]) => (
            (*action).to_string(),
            singularize(noun),
            (*target).to_string(),
        ),
        ("PATCH", [noun, target]) => (
            "update".to_string(),
            singularize(noun),
            (*target).to_string(),
        ),
        ("DELETE", [noun, target]) => (
            "delete".to_string(),
            singularize(noun),
            (*target).to_string(),
        ),
        ("POST", [noun]) => ("create".to_string(), singularize(noun), (*noun).to_string()),
        _ => (
            method.to_ascii_lowercase(),
            singularize(first),
            last.to_string(),
        ),
    }
}

fn infer_summary(method: &str, path: &str, body: &Value, ok: bool) -> Value {
    let (verb, noun, target) = infer_intent(method, path);
    if path.contains("/surfaces/") {
        let title = body
            .pointer("/document/header/title")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{} {}", verb, noun));
        let message = body
            .pointer("/document/summary")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                body.get("message")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "SOE surface render".to_string());
        let status = body
            .pointer("/document/header/state/execution")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| if ok { "ok".into() } else { "failed".into() });
        let why = body
            .pointer("/document/header/subject/display")
            .cloned()
            .or_else(|| body.get("detail").cloned());
        return serde_json::json!({
            "title": title,
            "message": message,
            "status": status,
            "why": why,
            "next": [
                format!("Inspect {} subject {}", noun, target)
            ]
        });
    }
    let message = body
        .get("message")
        .or_else(|| body.get("detail"))
        .and_then(|v| v.as_str())
        .unwrap_or("Request completed");
    serde_json::json!({
        "title": format!("{} {}", verb, noun),
        "message": message,
        "status": if ok { "completed" } else { "failed" },
        "why": body.get("detail"),
        "next": [
            format!("Review {} details for {}", noun, target)
        ]
    })
}

fn infer_trust(body: &Value) -> Value {
    // Only numeric scores from the response — do not invent scores from enum strings.
    // Absent stays absent: a missing score must not render as 0.0, which reads as
    // "fully untrusted" rather than "not measured".
    let score = body
        .pointer("/trust/score")
        .and_then(|v| v.as_f64())
        .or_else(|| body.pointer("/status/trust").and_then(|v| v.as_f64()));
    let grade = body
        .pointer("/trust/grade")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| body.get("trust_grade").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .or_else(|| {
            body.pointer("/document/header/state/trust")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "—".to_string());
    let verified = body
        .get("verified")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            body.pointer("/document/header/state/trust")
                .and_then(|v| v.as_str())
                .map(|s| s == "VERIFIED")
        })
        .unwrap_or(false);
    serde_json::json!({
        "score": score,
        "grade": grade,
        "verified": verified
    })
}

fn infer_evidence(body: &Value) -> Value {
    let mut evidence = Vec::new();
    if let Some(trace_id) = body.get("trace_id").and_then(|v| v.as_str()) {
        evidence.push(serde_json::json!({
            "kind": "trace",
            "id": trace_id,
            "label": "execution_trace",
            "verified": body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
        }));
    }
    for field in ["cid", "snapshot_cid", "root_cid"] {
        if let Some(cid) = body.get(field).and_then(|v| v.as_str()) {
            evidence.push(serde_json::json!({
                "kind": "cid",
                "id": cid,
                "label": field,
                "verified": true
            }));
        }
    }
    if let Some(cid) = body.pointer("/_meta/cid").and_then(|v| v.as_str()) {
        evidence.push(serde_json::json!({
            "kind": "cid",
            "id": cid,
            "label": "surface_cid",
            "verified": true
        }));
    }
    Value::Array(evidence)
}

fn infer_presentation(path: &str, body: &Value) -> Value {
    let mut mode = if path.ends_with('s') || path.contains("/list") {
        "list"
    } else {
        "detail"
    };
    let mut columns: Vec<String> = Vec::new();
    let mut row_count = None;

    if let Some(obj) = body.as_object() {
        for value in obj.values() {
            if let Some(items) = value.as_array() {
                if let Some(first) = items.first().and_then(|item| item.as_object()) {
                    columns = first.keys().take(8).cloned().collect();
                    row_count = Some(items.len());
                    mode = "list";
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "mode": mode,
        "table_safe": mode == "list",
        "row_count": row_count,
        "columns": columns
    })
}

/// Unwrap common server envelopes so the canonical `data` field is the resource payload:
/// - `{ ok, data }` (most platform routes)
/// - `{ data, meta }` without `ok` (books ledger `ApiResponse<T>`)
fn envelope_data_payload(body: &Value) -> Value {
    let Some(obj) = body.as_object() else {
        return body.clone();
    };
    // Books: { data: T, meta: ApiMeta }
    if obj.contains_key("data") && obj.contains_key("meta") && !obj.contains_key("ok") {
        return obj.get("data").cloned().unwrap_or_else(|| body.clone());
    }
    if obj.contains_key("ok") && obj.contains_key("data") {
        return obj.get("data").cloned().unwrap_or_else(|| body.clone());
    }
    body.clone()
}

fn normalize_success_response(method: &str, path: &str, body: Value) -> Value {
    if is_canonical_result(&body) {
        return body;
    }

    let (verb, noun, target) = infer_intent(method, path);
    let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
    let data_inner = envelope_data_payload(&body);
    let mut envelope = serde_json::json!({
        "ok": ok,
        "intent": {
            "verb": verb,
            "noun": noun,
            "target": target
        },
        "summary": infer_summary(method, path, &body, ok),
        "trust": infer_trust(&body),
        "evidence": infer_evidence(&body),
        "links": {
            "docs": "/docs"
        },
        "render": {
            "role": "operator",
            "redacted": false,
            "redacted_fields": []
        },
        "presentation": infer_presentation(path, &body),
        "meta": {
            "schema": "connector.result.v1",
            "family": "canonical_semantic_package",
            "package_first": true,
            "view": "package",
            "source": "dashboard-ui"
        },
        "data": data_inner
    });

    if let Some(obj) = body.as_object() {
        if let Some(envelope_obj) = envelope.as_object_mut() {
            for (key, value) in obj {
                envelope_obj
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    envelope
}

/// After [`get_value`] / [`post_value`], the canonical envelope stores the unwrapped resource in
/// `data` and merges original body keys at the top level. This returns the object to prefer for
/// nested reads (`data` when non-null).
pub fn resource_object(v: &Value) -> &Value {
    match v.get("data") {
        Some(d) if !d.is_null() => d,
        _ => v,
    }
}

/// Resolve a field from either the merged top-level keys or [`resource_object`].
pub fn resource_get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key).or_else(|| resource_object(v).get(key))
}

/// Clone an array field from a normalized API value (empty vec if missing).
pub fn resource_array(v: &Value, key: &str) -> Vec<Value> {
    resource_get(v, key)
        .and_then(|a| a.as_array())
        .map(|arr| arr.clone())
        .unwrap_or_default()
}

async fn parse_error(resp: gloo_net::http::Response) -> ApiError {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let parsed = serde_json::from_str::<Value>(&text)
        .unwrap_or_else(|_| serde_json::json!({ "message": text }));
    let error = parsed.get("error").unwrap_or(&parsed);

    let mut hints: Vec<String> = error
        .get("hints")
        .or_else(|| error.get("hint"))
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if hints.is_empty() {
        if let Some(h) = parsed.get("hint").and_then(|v| v.as_str()) {
            hints.push(h.to_string());
        } else if let Some(h) = error.get("hint").and_then(|v| v.as_str()) {
            hints.push(h.to_string());
        }
    }
    // Surface HITL / problem+json example so Talk can approve by id.
    for key in ["quarantine_hitl_id", "example", "hitl_request_id", "request_id"] {
        if let Some(s) = parsed
            .get(key)
            .or_else(|| error.get(key))
            .and_then(|v| v.as_str())
        {
            if !s.is_empty() && !hints.iter().any(|h| h.contains(s)) {
                hints.push(format!("{key}:{s}"));
            }
        }
    }

    let code = parsed
        .get("code")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .or_else(|| {
            error
                .get("code")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        })
        .or_else(|| {
            parsed
                .get("error")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        })
        .or_else(|| {
            error
                .get("denial_reason")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        });

    let nested = parsed
        .pointer("/body/error/message")
        .or_else(|| parsed.pointer("/error/message"))
        .or_else(|| parsed.pointer("/body/message"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let message = nested.unwrap_or_else(|| {
        if let Some(s) = parsed.get("error").and_then(|v| v.as_str()) {
            s.to_string()
        } else if let Some(d) = error.get("detail").and_then(|v| v.as_str()) {
            d.to_string()
        } else if let Some(d) = parsed.get("detail").and_then(|v| v.as_str()) {
            d.to_string()
        } else {
            error
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Request failed")
                .to_string()
        }
    });

    let detail = error
        .get("detail")
        .and_then(|v| v.as_str())
        .or_else(|| parsed.get("detail").and_then(|v| v.as_str()))
        .map(|v| v.to_string())
        .or_else(|| {
            // Keep HITL UUID in detail for approve_unquarantine_hitl extractors.
            hints
                .iter()
                .find(|h| h.contains("hitl") || h.contains("request_id") || h.starts_with("example:"))
                .cloned()
        });

    ApiError {
        status,
        code,
        message,
        detail,
        hints,
        docs: error
            .get("docs")
            .and_then(|v| v.as_str())
            .or_else(|| parsed.get("docs").and_then(|v| v.as_str()))
            .map(|v| v.to_string()),
    }
}

fn get_token() -> Option<String> {
    LocalStorage::get::<String>("access_token").ok()
}

fn set_tokens(access: &str, refresh: &str) {
    let _ = LocalStorage::set("access_token", access);
    let _ = LocalStorage::set("refresh_token", refresh);
}

pub fn clear_tokens() {
    let _ = LocalStorage::delete("access_token");
    let _ = LocalStorage::delete("refresh_token");
}

async fn try_refresh() -> bool {
    let refresh_token = match LocalStorage::get::<String>("refresh_token") {
        Ok(t) => t,
        Err(_) => return false,
    };
    let body = serde_json::json!({ "refresh_token": refresh_token });
    let resp = Request::post(&format!("{BASE}/auth/refresh"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .unwrap()
        .send()
        .await;
    match resp {
        Ok(r) if r.ok() => {
            if let Ok(data) = r.json::<Value>().await {
                let access = data["access_token"].as_str().unwrap_or("").to_string();
                let refresh = data["refresh_token"].as_str().unwrap_or("").to_string();
                if !access.is_empty() {
                    set_tokens(&access, &refresh);
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

async fn raw_fetch(
    method: &str,
    url: &str,
    body: Option<String>,
) -> Result<gloo_net::http::Response, ApiError> {
    let token = get_token();
    let mut builder = match method {
        "GET" => Request::get(url),
        "POST" => Request::post(url),
        "PUT" => Request::put(url),
        "PATCH" => Request::patch(url),
        "DELETE" => Request::delete(url),
        _ => Request::get(url),
    }
    .header("Content-Type", "application/json")
    .header("Accept", "application/json");

    if let Some(t) = &token {
        builder = builder.header("Authorization", &format!("Bearer {t}"));
    }
    if let Ok(tid) = LocalStorage::get::<String>("tenant_id") {
        if !tid.trim().is_empty() {
            builder = builder.header("X-Tenant-Id", tid.trim());
        }
    }

    let req = if let Some(b) = body {
        builder.body(b).map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?
    } else {
        builder.build().map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?
    };

    req.send().await.map_err(|e| ApiError {
        status: 0,
        code: None,
        message: e.to_string(),
        detail: None,
        hints: Vec::new(),
        docs: None,
    })
}

const DEFAULT_API_TIMEOUT_MS: u32 = 20_000;
/// Talk/completions may wait on upstream LLM (server allows ~60s).
pub const TALK_COMPLETIONS_TIMEOUT_MS: u32 = 120_000;

fn timeout_error(path: &str, timeout_ms: u32) -> ApiError {
    let is_talk = path.contains("/completions");
    if is_talk {
        ApiError {
            status: 0,
            code: Some("timeout".into()),
            message: format!(
                "Talk timed out after {}s waiting for the LLM reply.",
                timeout_ms / 1000
            ),
            detail: None,
            hints: vec![
                "Retry — DeepSeek and other providers can be slow on first turn.".into(),
                "Check Settings → LLM if this repeats (key, model, provider status).".into(),
            ],
            docs: None,
        }
    } else {
        ApiError {
            status: 0,
            code: Some("timeout".into()),
            message: format!("Request timed out after {}s.", timeout_ms / 1000),
            detail: None,
            hints: vec![
                "If developing locally: start connector-platform, then click ↻ in the pulse bar.".into(),
                "Trunk dev proxies /api → http://localhost:9091/api.".into(),
            ],
            docs: None,
        }
    }
}

async fn with_timeout_ms<T>(
    timeout_ms: u32,
    path: &str,
    fut: impl std::future::Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    use futures::{FutureExt, pin_mut, select};
    use gloo_timers::future::TimeoutFuture;

    let timeout = TimeoutFuture::new(timeout_ms).fuse();
    let work = fut.fuse();
    pin_mut!(timeout, work);
    select! {
        res = work => res,
        _ = timeout => Err(timeout_error(path, timeout_ms)),
    }
}

async fn with_timeout<T>(
    path: &str,
    fut: impl std::future::Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    with_timeout_ms(DEFAULT_API_TIMEOUT_MS, path, fut).await
}

pub async fn api_fetch<T: DeserializeOwned>(
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<T, ApiError> {
    with_timeout(path, api_fetch_inner(method, path, body)).await
}

pub async fn api_fetch_timeout<T: DeserializeOwned>(
    method: &str,
    path: &str,
    body: Option<Value>,
    timeout_ms: u32,
) -> Result<T, ApiError> {
    with_timeout_ms(timeout_ms, path, api_fetch_inner(method, path, body)).await
}

async fn api_fetch_inner<T: DeserializeOwned>(
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<T, ApiError> {
    let url = api_url(path);
    let body_str = body.map(|b| b.to_string());

    let resp = raw_fetch(method, &url, body_str.clone()).await?;

    if resp.status() == 401 {
        if try_refresh().await {
            // Retry with new token
            let resp2 = raw_fetch(method, &url, body_str).await?;
            if resp2.ok() {
                return resp2.json::<T>().await.map_err(|e| ApiError {
                    status: 200,
                    code: None,
                    message: e.to_string(),
                    detail: None,
                    hints: Vec::new(),
                    docs: None,
                });
            }
        }
        clear_tokens();
        // Let caller handle redirect via Leptos <Redirect> — avoid hard reload loops
        return Err(ApiError {
            status: 401,
            code: Some("auth_required".into()),
            message: "Unauthorized".into(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        });
    }

    if !resp.ok() {
        return Err(parse_error(resp).await);
    }

    resp.json::<T>().await.map_err(|e| ApiError {
        status: 200,
        code: Some("parse_error".into()),
        message: format!("Parse error: {e}"),
        detail: None,
        hints: Vec::new(),
        docs: None,
    })
}

async fn raw_fetch_bytes(
    method: &str,
    url: &str,
    body: Option<String>,
) -> Result<gloo_net::http::Response, ApiError> {
    let token = get_token();
    let mut builder = match method {
        "GET" => Request::get(url),
        "POST" => Request::post(url),
        "PUT" => Request::put(url),
        "PATCH" => Request::patch(url),
        "DELETE" => Request::delete(url),
        _ => Request::get(url),
    }
    .header("Accept", "application/pdf, application/octet-stream, */*");

    if body.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }

    if let Some(t) = &token {
        builder = builder.header("Authorization", &format!("Bearer {t}"));
    }
    if let Ok(tid) = LocalStorage::get::<String>("tenant_id") {
        if !tid.trim().is_empty() {
            builder = builder.header("X-Tenant-Id", tid.trim());
        }
    }

    let req = if let Some(b) = body {
        builder.body(b).map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?
    } else {
        builder.build().map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?
    };

    req.send().await.map_err(|e| ApiError {
        status: 0,
        code: None,
        message: e.to_string(),
        detail: None,
        hints: Vec::new(),
        docs: None,
    })
}

async fn api_fetch_bytes(method: &str, path: &str, body: Option<Value>) -> Result<Vec<u8>, ApiError> {
    let url = api_url(path);
    let body_str = body.map(|b| b.to_string());
    let mut resp = raw_fetch_bytes(method, &url, body_str.clone()).await?;

    if resp.status() == 401 {
        if try_refresh().await {
            resp = raw_fetch_bytes(method, &url, body_str).await?;
            if resp.ok() {
                return resp.binary().await.map_err(|e| ApiError {
                    status: 200,
                    code: None,
                    message: e.to_string(),
                    detail: None,
                    hints: Vec::new(),
                    docs: None,
                });
            }
        }
        clear_tokens();
        return Err(ApiError {
            status: 401,
            code: Some("auth_required".into()),
            message: "Unauthorized".into(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        });
    }

    if !resp.ok() {
        return Err(parse_error(resp).await);
    }

    resp.binary().await.map_err(|e| ApiError {
        status: 200,
        code: None,
        message: e.to_string(),
        detail: None,
        hints: Vec::new(),
        docs: None,
    })
}

/// Authenticated GET returning raw bytes (e.g. report document export).
pub async fn get_bytes(path: &str) -> Result<Vec<u8>, ApiError> {
    api_fetch_bytes("GET", path, None).await
}

/// Authenticated POST with JSON body; response is raw bytes (e.g. `.cpkg` bundle export).
pub async fn post_bytes(path: &str, body: Value) -> Result<Vec<u8>, ApiError> {
    api_fetch_bytes("POST", path, Some(body)).await
}

// ─── Convenience wrappers ────────────────────────────────────────────────────

pub async fn get<T: DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    api_fetch("GET", path, None).await
}

pub async fn get_q<T: DeserializeOwned>(
    path: &str,
    params: &[(&str, &str)],
) -> Result<T, ApiError> {
    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let full = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    api_fetch("GET", &full, None).await
}

pub async fn post<T: DeserializeOwned>(path: &str, body: Value) -> Result<T, ApiError> {
    api_fetch("POST", path, Some(body)).await
}

pub async fn delete<T: DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    api_fetch("DELETE", path, None).await
}

/// Fetch raw JSON Value without deserializing to a specific type
pub async fn get_value(path: &str) -> Result<Value, ApiError> {
    get::<Value>(path)
        .await
        .map(|value| normalize_success_response("GET", path, value))
}

/// The error a 2xx response is carrying, if it is actually a failure.
///
/// Many handlers answer HTTP 200 with `{"ok": false, "error": ...}`, so a bare
/// `Ok(_)` from the helpers below is not evidence that the write succeeded.
/// Callers that report success to the operator must consult this first.
pub fn body_error(v: &Value) -> Option<String> {
    body_failure_detail(v)
}

/// Richer operator-facing failure text: error + reason + hint + quarantine_hitl_id.
pub fn body_failure_detail(v: &Value) -> Option<String> {
    if v.get("ok").and_then(|x| x.as_bool()) != Some(false) {
        return None;
    }
    let err = v
        .get("error")
        .or_else(|| v.get("message"))
        .and_then(|x| x.as_str())
        .unwrap_or("Request failed");
    let mut parts = vec![err.to_string()];
    if let Some(r) = v.get("reason").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        parts.push(format!("reason={r}"));
    }
    if let Some(h) = v
        .get("hint")
        .and_then(|x| x.as_str())
        .or_else(|| {
            v.get("hints")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.as_str())
        })
        .filter(|s| !s.is_empty())
    {
        parts.push(format!("hint={h}"));
    }
    if let Some(id) = v
        .get("quarantine_hitl_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        parts.push(format!("hitl={id}"));
    }
    Some(parts.join(" · "))
}

pub async fn post_value(path: &str, body: Value) -> Result<Value, ApiError> {
    post::<Value>(path, body)
        .await
        .map(|value| normalize_success_response("POST", path, value))
}

pub async fn post_value_timeout(path: &str, body: Value, timeout_ms: u32) -> Result<Value, ApiError> {
    api_fetch_timeout::<Value>("POST", path, Some(body), timeout_ms)
        .await
        .map(|value| normalize_success_response("POST", path, value))
}

/// GET with an explicit client timeout (e.g. LLM status must not sit on the 20s default).
pub async fn get_value_timeout(path: &str, timeout_ms: u32) -> Result<Value, ApiError> {
    api_fetch_timeout::<Value>("GET", path, None, timeout_ms)
        .await
        .map(|value| normalize_success_response("GET", path, value))
}

/// PUT helper that returns a raw `Value`. Mirrors [`post_value`].
///
/// Added in Phase 7 / P2-24 for the `connector.yaml` editor which
/// needs an idempotent write. Other callers may use it for any
/// resource that prefers PUT semantics.
pub async fn put_value(path: &str, body: Value) -> Result<Value, ApiError> {
    api_fetch::<Value>("PUT", path, Some(body))
        .await
        .map(|value| normalize_success_response("PUT", path, value))
}

/// PATCH helper that returns a raw `Value` (e.g. notification acknowledge).
pub async fn patch_value(path: &str, body: Value) -> Result<Value, ApiError> {
    api_fetch::<Value>("PATCH", path, Some(body))
        .await
        .map(|value| normalize_success_response("PATCH", path, value))
}

pub async fn delete_value(path: &str) -> Result<Value, ApiError> {
    api_fetch::<Value>("DELETE", path, None)
        .await
        .map(|value| normalize_success_response("DELETE", path, value))
}

pub async fn get_value_q(path: &str, params: &[(&str, &str)]) -> Result<Value, ApiError> {
    get_q::<Value>(path, params)
        .await
        .map(|value| normalize_success_response("GET", path, value))
}
