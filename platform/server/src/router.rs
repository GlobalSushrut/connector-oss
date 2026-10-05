use axum::{Router, routing::{get, post, put, delete}, http::StatusCode, response::IntoResponse};
use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, Response};
use std::path::{Component, Path, PathBuf};
use crate::state::{AgentLabels, NamespaceLabels, SharedState};
use crate::services;
use crate::auth;
use crate::services::runtime_control::RuntimeMode;
use crate::middleware::otel::trace_context_middleware;
use crate::middleware::rate_limit::rate_limit_middleware;

// =============================================================================
// XDX-6: Dev-mode request log — ring buffer of last 100 requests.
// Only populated when CONNECTOR_ENV=development. GET /dev/requests returns it.
// =============================================================================
use std::sync::Mutex as StdMutex;

pub static DEV_REQUEST_LOG: StdMutex<std::collections::VecDeque<serde_json::Value>> =
    StdMutex::new(std::collections::VecDeque::new());

const DEV_REQUEST_LOG_SIZE: usize = 100;

/// Push one request entry into the dev ring-buffer (no-op outside dev mode).
pub fn dev_log_push(entry: serde_json::Value) {
    if let Ok(mut log) = DEV_REQUEST_LOG.lock() {
        if log.len() >= DEV_REQUEST_LOG_SIZE {
            log.pop_front();
        }
        log.push_back(entry);
    }
}

pub fn resolve_dashboard_ui_dir() -> String {
    if let Ok(explicit) = std::env::var("CONNECTOR_UI_DIR") {
        return explicit;
    }

    for candidate in dashboard_ui_dir_candidates() {
        if dashboard_ui_index_file(&candidate).is_some() {
            return candidate.to_string_lossy().to_string();
        }
    }

    "./ui-leptos/dashboard/dist".into()
}

/// Operator-facing label for which UI tree the HTTP server will serve.
pub fn dashboard_ui_mount_label() -> String {
    let dir = resolve_dashboard_ui_dir();
    if dashboard_ui_index_file(Path::new(&dir)).is_some() {
        format!("filesystem:{dir}")
    } else {
        crate::dashboard_embed::embed_mount_label().into()
    }
}

/// True when the asset filename embeds a content hash (immutable cache-safe).
pub fn is_content_hashed_asset(key: &str) -> bool {
    let name = key.rsplit('/').next().unwrap_or(key);
    // e.g. app-a1b2c3d4.js / style.abcdef012345.css
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    stem.contains('-')
        && stem
            .rsplit('-')
            .next()
            .map(|h| h.len() >= 8 && h.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false)
}

fn dashboard_ui_dir_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![
        PathBuf::from("./ui-leptos/dashboard/dist"),
        PathBuf::from("../ui-leptos/dashboard/dist"),
        PathBuf::from("platform/ui-leptos/dashboard/dist"),
    ];

    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join(".local/share/connector/ui"));
    }

    if let Ok(exe) = std::env::current_exe() {
        for base in exe.ancestors().take(5) {
            candidates.push(base.join("../ui-leptos/dashboard/dist"));
            candidates.push(base.join("../../ui-leptos/dashboard/dist"));
            candidates.push(base.join("../share/connector/ui"));
            candidates.push(base.join("../../share/connector/ui"));
        }
    }

    candidates
}

fn dashboard_ui_index_file(dir: &Path) -> Option<PathBuf> {
    ["index.html", "index.release.html"]
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists())
}

fn ui_mime(rel: &str) -> &'static str {
    let l = rel.to_ascii_lowercase();
    if l.ends_with(".js") || l.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if l.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if l.ends_with(".wasm") {
        "application/wasm"
    } else if l.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if l.ends_with(".svg") {
        "image/svg+xml"
    } else if l.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if l.ends_with(".png") {
        "image/png"
    } else if l.ends_with(".ico") {
        "image/x-icon"
    } else if l.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}

fn wants_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|p| p.trim().starts_with("gzip")))
        .unwrap_or(false)
}

fn is_trial_shell_path(path: &str) -> bool {
    matches!(path, "/login" | "/trial" | "/connect")
        || path.starts_with("/login/")
        || path.starts_with("/trial/")
        || path.starts_with("/connect/")
}

fn looks_like_static_asset(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.contains('.')
        && !name.ends_with('.')
        && Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .is_some()
}

fn safe_ui_file(ui_dir: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = PathBuf::from(ui_dir);
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if out.exists() && out.is_file() {
        Some(out)
    } else {
        None
    }
}

fn cache_control_for(rel: &str) -> &'static str {
    if rel.ends_with(".html") {
        return "no-cache, no-store, must-revalidate";
    }
    if is_content_hashed_asset(rel) {
        return "public, max-age=31536000, immutable";
    }
    if rel.ends_with(".wasm") || rel.ends_with(".js") || rel.ends_with(".css") {
        return "public, max-age=31536000, immutable";
    }
    "public, max-age=3600"
}

/// Disk UI with gzip siblings + playground trial-app shell for /login /trial /connect.
/// Restores the WASM loading path documented in platform/deploy/WASM_LOADING.md.
async fn serve_with_compression(req: Request<Body>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .unwrap();
    }
    let ui_dir = PathBuf::from(resolve_dashboard_ui_dir());
    let raw_path = req.uri().path();
    let path = raw_path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let wants_head = req.method() == Method::HEAD;
    let gzip_ok = wants_gzip(req.headers());
    let playground = services::playground::is_playground_mode()
        || std::env::var("CONNECTOR_PRESET")
            .map(|v| v.eq_ignore_ascii_case("playground"))
            .unwrap_or(false);

    if playground && is_trial_shell_path(path) {
        let trial_index = ui_dir.join("trial-app").join("index.html");
        if trial_index.is_file() {
            return file_response(&trial_index, "text/html; charset=utf-8", gzip_ok, wants_head, "no-cache, no-store, must-revalidate");
        }
    }

    let rel = path.trim_start_matches('/');
    if !rel.is_empty() {
        if let Some(file) = safe_ui_file(&ui_dir, rel) {
            let mime = ui_mime(rel);
            let cache = cache_control_for(rel);
            return file_response(&file, mime, gzip_ok, wants_head, cache);
        }
    }

    if looks_like_static_asset(path) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    }

    // SPA fallback — full dashboard WASM (gzipped when sibling exists)
    if let Some(index) = dashboard_ui_index_file(&ui_dir) {
        return file_response(
            &index,
            "text/html; charset=utf-8",
            gzip_ok,
            wants_head,
            "no-cache, no-store, must-revalidate",
        );
    }
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("dashboard UI not found"))
        .unwrap()
}

fn file_response(
    path: &Path,
    mime: &str,
    gzip_ok: bool,
    head: bool,
    cache: &str,
) -> Response<Body> {
    let gz = PathBuf::from(format!("{}.gz", path.display()));
    let (bytes, encoding) = if gzip_ok && gz.is_file() {
        (std::fs::read(&gz).ok(), Some("gzip"))
    } else {
        (std::fs::read(path).ok(), None)
    };
    let Some(bytes) = bytes else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    };
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache)
        .header(header::VARY, "Accept-Encoding");
    if let Some(enc) = encoding {
        b = b.header(header::CONTENT_ENCODING, enc);
    }
    let body = if head { Body::empty() } else { Body::from(bytes) };
    b.body(body).unwrap()
}

// ── DX-P2-2: Auth middleware for the entire api router ────────────────────────
// Routes matching the allowlist bypass token verification (public endpoints).
// All other /api/v1/* requests must carry a valid Bearer JWT or cpk_live_* key.
async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<SharedState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;

    // Paths that do not require authentication
    // FIX BUG-043: Added /auth/login, /auth/refresh, /auth/logout
    // FIX BUG-044: Added /billing/stripe/webhook (uses Stripe-Signature, not JWT)
    const ALLOWLIST: &[&str] = &[
        "/auth/signup",
        "/auth/token",
        "/auth/login",
        "/auth/refresh",
        "/auth/logout",
        "/auth/sso",
        "/auth/sso/login",
        "/auth/sso/callback",
        "/auth/totp/verify",
        "/billing/stripe/webhook",
        "/payment/webhook",
        "/license/status",
        "/license/activate",
        "/license/machine",
        "/runtime/activation",
        // Hosted trial: email gate starts a session without a prior token
        "/playground/status",
        "/playground/session",
    ];

    let path = req.uri().path();

    // Strip /api/v1 or /api/v2 prefix (middleware may run on nested or absolute paths)
    let path_bare = path
        .strip_prefix("/api/v1")
        .or_else(|| path.strip_prefix("/api/v2"))
        .unwrap_or(path);
    // BF2-S04: segment-safe public routes — do not treat `/auth/signup` as a prefix for `/auth/signup/evil`.
    let path_norm = path_bare.trim_end_matches('/');

    let is_public = ALLOWLIST.iter().any(|p| path_norm == *p)
        // Opaque session id status/end (not export / not admin list)
        || ((req.method() == axum::http::Method::GET || req.method() == axum::http::Method::DELETE)
            && path_norm.starts_with("/playground/session/")
            && !path_norm.ends_with("/export"));

    if is_public {
        return next.run(req).await;
    }

    // BF2-O01: authoritative runtime mode from store (applied at boot / runtime control), not raw CONNECTOR_ENV alone.
    let runtime_mode = *state.runtime_mode.read().unwrap();

    let forbid_rbac = |why: String| -> axum::response::Response {
        let body = serde_json::json!({
            "ok": false,
            "error": {
                "code": "forbidden",
                "message": why,
                "status": 403
            }
        });
        (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
    };

    let enforce = |claims: &crate::auth::Claims, path_bare: &str, method: &str| -> Option<String> {
        crate::auth::rbac::enforce_rest_access(
            claims,
            path_bare.trim_start_matches('/'),
            method,
        )
    };

    let tenant_spoof = |claims: &crate::auth::Claims,
                        headers: &axum::http::HeaderMap|
     -> Option<String> {
        let multi = std::env::var("CONNECTOR_MULTI_TENANT")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if !multi {
            return None;
        }
        let Some(bound) = claims.tenant_id.as_deref().filter(|s| !s.is_empty()) else {
            return None;
        };
        let header_tenant = headers
            .get("x-tenant-id")
            .or_else(|| headers.get("X-Tenant-ID"))
            .and_then(|h| h.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(hdr) = header_tenant {
            if hdr != bound {
                return Some(format!(
                    "X-Tenant-ID {hdr} does not match credential tenant {bound}"
                ));
            }
        }
        None
    };

    // FIX BUG-045: Check X-API-Key header first
    if let Some(api_key) = req.headers().get("x-api-key").and_then(|h| h.to_str().ok()) {
        if api_key.starts_with("cpk_") {
            match crate::auth::claims_for_api_key(api_key) {
                Ok(claims) => {
                    if api_key.starts_with("cpk_pilot_") && !matches!(runtime_mode, RuntimeMode::Pilots) {
                        let body = serde_json::json!({
                            "ok": false,
                            "error": {
                                "code": "pilot_key_wrong_mode",
                                "message": "Pilot keys are only valid when the node is running in pilots mode.",
                                "status": 403
                            }
                        });
                        return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
                    }
                    if let RuntimeMode::Pilots = runtime_mode {
                        if let Ok(scopes) = crate::auth::api_key_scopes(api_key) {
                            if !services::runtime_control::pilot_scope_allows(path_bare, req.method().as_str(), &scopes) {
                                let body = serde_json::json!({
                                    "ok": false,
                                    "error": {
                                        "code": "pilot_scope_denied",
                                        "message": "Pilot API key does not allow this endpoint.",
                                        "hint": "Extend the pilot scope with connectorctl admin pilot scope <pilot_id> --add=<scope>",
                                        "status": 403
                                    }
                                });
                                return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
                            }
                        }
                    }
                    if let Some(why) = enforce(&claims, path_bare, req.method().as_str()) {
                        return forbid_rbac(why);
                    }
                    if let Some(why) = tenant_spoof(&claims, req.headers()) {
                        return forbid_rbac(why);
                    }
                    req.extensions_mut().insert(claims.clone());
                    req.extensions_mut()
                        .insert(connector_trust::PrincipalContextV2::from(&claims));
                    return next.run(req).await;
                }
                Err(_) => { /* fall through to Bearer */ }
            }
        }
    }

    let token = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    if token.is_empty() {
        let body = serde_json::json!({
            "ok": false,
            "error": {
                "code": "authentication_required",
                "message": "Request is missing a valid Authorization header. Use: Authorization: Bearer <token>",
                "hint": "Obtain a token via POST /api/v1/auth/token or create an API key via POST /api/v1/auth/api-keys",
                "docs": "https://connector.ai/docs/errors/authentication_required",
                "status": 401
            }
        });
        return (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response();
    }

    if matches!(runtime_mode, RuntimeMode::Dev) && services::runtime_control::dev_auth_bypass_allowed() {
        // Any non-empty token accepted in dev mode (honors CONNECTOR_DEFENSE_STRICT / prod env)
        return next.run(req).await;
    }

    // FIX BUG-045: Also accept cpk_* API keys in Bearer header
    if token.starts_with("cpk_") {
        match crate::auth::claims_for_api_key(token) {
            Ok(claims) => {
                if token.starts_with("cpk_pilot_") && !matches!(runtime_mode, RuntimeMode::Pilots) {
                    let body = serde_json::json!({
                        "ok": false,
                        "error": {
                            "code": "pilot_key_wrong_mode",
                            "message": "Pilot keys are only valid when the node is running in pilots mode.",
                            "status": 403
                        }
                    });
                    return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
                }
                if let RuntimeMode::Pilots = runtime_mode {
                    if let Ok(scopes) = crate::auth::api_key_scopes(token) {
                        if !services::runtime_control::pilot_scope_allows(path_bare, req.method().as_str(), &scopes) {
                            let body = serde_json::json!({
                                "ok": false,
                                "error": {
                                    "code": "pilot_scope_denied",
                                    "message": "Pilot API key does not allow this endpoint.",
                                    "hint": "Extend the pilot scope with connectorctl admin pilot scope <pilot_id> --add=<scope>",
                                    "status": 403
                                }
                            });
                            return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
                        }
                    }
                }
                if let Some(why) = enforce(&claims, path_bare, req.method().as_str()) {
                    return forbid_rbac(why);
                }
                if let Some(why) = tenant_spoof(&claims, req.headers()) {
                    return forbid_rbac(why);
                }
                let mut principal = connector_trust::PrincipalContextV2::from(&claims);
                principal.auth_source = connector_trust::principal::AuthSourceV2::ApiKey;
                req.extensions_mut().insert(claims);
                req.extensions_mut().insert(principal);
                return next.run(req).await;
            }
            Err(_) => {
                let body = serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "invalid_api_key",
                        "message": "API key is invalid or revoked.",
                        "hint": "Create a new API key via POST /api/v1/auth/api-keys",
                        "docs": "https://connector.ai/docs/errors/invalid_api_key",
                        "status": 401
                    }
                });
                return (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response();
            }
        }
    }

    // Production: validate JWT + RBAC
    match crate::auth::verify_token(token) {
        Ok(claims) => {
            if let Some(why) = enforce(&claims, path_bare, req.method().as_str()) {
                return forbid_rbac(why);
            }
            if let Some(why) = tenant_spoof(&claims, req.headers()) {
                return forbid_rbac(why);
            }
            req.extensions_mut()
                .insert(connector_trust::PrincipalContextV2::from(&claims));
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(_) => {
            let body = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "authentication_required",
                    "message": "Bearer token is invalid or expired.",
                    "hint": "Re-authenticate via POST /api/v1/auth/token to get a fresh JWT.",
                    "docs": "https://connector.ai/docs/errors/authentication_required",
                    "status": 401
                }
            });
            (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
        }
    }
}

// =============================================================================
// XDX-6: Dev-mode request logging middleware.
// Logs method + path + status + latency to stdout AND pushes into DEV_REQUEST_LOG.
// Only active when CONNECTOR_ENV=development or CONNECTOR_DEV_MODE=1.
// =============================================================================
async fn dev_log_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // BF2-O02: align with defense posture — no noisy request logging when dev bypass is disallowed.
    if !crate::services::runtime_control::dev_auth_bypass_allowed() {
        return next.run(req).await;
    }

    let method = req.method().to_string();
    let path   = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
    let start  = std::time::Instant::now();
    let ts_ms  = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;

    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let latency_ms = start.elapsed().as_millis() as u64;

    // XDX-6: log format mirrors curl: [→] METHOD /path STATUS latency
    println!("[→] {} {} {} {}ms", method, path, status, latency_ms);

    // Push to dev ring-buffer
    dev_log_push(serde_json::json!({
        "ts_ms":      ts_ms,
        "method":     method,
        "path":       path,
        "status":     status,
        "latency_ms": latency_ms,
    }));

    resp
}

// =============================================================================
// XDX-5: Connector-Version response header middleware.
// Adds `Connector-Version: <semver>` to every API response so clients can
// pin a version and detect upgrades without polling /version.
// =============================================================================
async fn connector_version_header_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let version = env!("CARGO_PKG_VERSION");
    if let Ok(val) = axum::http::HeaderValue::from_str(version) {
        resp.headers_mut().insert("Connector-Version", val);
    }
    resp
}

// ── Deprecation header helper ─────────────────────────────────────────────────
// Wraps a Router so every response from it gains:
//   Deprecated: true
//   Sunset: <version>
//   Link: <canonical>; rel="successor-version"
fn with_deprecation_headers(
    router: Router<SharedState>,
    use_instead: &'static str,
    will_remove: &'static str,
) -> Router<SharedState> {
    use axum::middleware::{self, Next};
    use axum::http::Request;
    let use_instead_val = use_instead;
    let will_remove_val = will_remove;
    router.layer(middleware::from_fn(
        move |req: Request<axum::body::Body>, next: Next| {
            let use_instead_v = use_instead_val;
            let will_remove_v = will_remove_val;
            async move {
                let mut resp = next.run(req).await;
                let headers = resp.headers_mut();
                headers.insert(
                    "Deprecated",
                    axum::http::HeaderValue::from_static("true"),
                );
                headers.insert(
                    "Sunset",
                    axum::http::HeaderValue::from_static(will_remove_v),
                );
                if let Ok(val) = axum::http::HeaderValue::from_str(
                    &format!("{}", use_instead_v)
                ) {
                    headers.insert("Link", val);
                }
                resp
            }
        }
    ))
}

pub fn build_router(state: SharedState) -> Router {
    let api = Router::new()
        // ── Service 1: Debug ─────────────────────────────────
        .route("/debug/sessions", get(services::debug::list_sessions))
        .route("/debug/sessions/:session_id", get(services::debug::session_detail))
        .route("/debug/audit", get(services::debug::audit_log))
        .route("/debug/memory/:cid", get(services::debug::memory_recall))
        .route("/debug/export", get(services::debug::kernel_export))
        .route("/debug/agents/:agent_pid/permissions", get(services::debug::agent_permissions))
        .route("/debug/agents/:agent_pid/tool-trace", get(services::debug::agent_tool_trace))
        .route("/debug/agents/:agent_pid/snapshot", get(services::debug::agent_snapshot))
        .route("/debug/agents/:agent_pid/reasoning-chain", get(services::debug::agent_reasoning_chain))
        .route("/debug/agents/:agent_pid/restore", post(services::debug::agent_restore))
        .route("/debug/agents/:agent_pid/bindings", get(services::debug::agent_bindings))
        .route("/debug/agents/:agent_pid/bind-tool", post(services::debug::bind_tool))
        .route("/debug/agents/:agent_pid/role", post(services::debug::set_role))
        // E4.1-E4.3: Run diff, failure clusters, live trace stream
        .route("/debug/diff", get(services::debug::run_diff))
        .route("/debug/failure-clusters", get(services::debug::failure_clusters))
        .route("/debug/agents/:agent_pid/trace/stream", get(services::debug::trace_stream))
        // 2.5: OpenTelemetry trace inspection endpoints
        .route("/debug/traces", get(services::debug::list_traces))
        .route("/debug/traces/stats", get(services::debug::trace_stats))
        .route("/debug/traces/:trace_id", get(services::debug::get_trace))
        .route("/debug/surface/:subject_id", get(services::debug::surface_contract_json))
        .route("/surfaces/:surface/:subject_id", get(services::surfaces::render_surface_json))

        // ── Service 2: Action Log ────────────────────────────
        .route("/actionlog/record", post(services::actionlog::record_action))
        .route("/actionlog/actions", get(services::actionlog::list_actions))
        .route("/actionlog/interactions", get(services::actionlog::list_interactions))
        .route("/actionlog/denied", get(services::actionlog::denied_operations))
        .route("/actionlog/access-matrix", get(services::actionlog::access_matrix))
        .route("/actionlog/compliance-gaps", get(services::actionlog::compliance_gaps))
        .route("/actionlog/tool-audit", get(services::actionlog::tool_audit))
        .route("/actionlog/regulation-report/:framework", get(services::actionlog::regulation_report))
        .route("/actionlog/pii-scan", get(services::actionlog::pii_scan))
        // E1.1-E1.4 / E6.1-E6.5: Enterprise audit exports + dependency map
        .route("/actionlog/export/otel", get(services::actionlog::export_otel))
        .route("/actionlog/export/jsonl", get(services::actionlog::export_jsonl))
        .route("/actionlog/export/cloudevents", get(services::actionlog::export_cloudevents))
        .route("/actionlog/chargeback-report", get(services::actionlog::chargeback_report))
        .route("/actionlog/subject-access", get(services::actionlog::subject_access))
        .route("/actionlog/dependency-map", get(services::actionlog::dependency_map))

        // ── Service 3: Proof of Work ─────────────────────────
        .route("/proof/generate", post(services::proof::generate_proof))
        .route("/proof/list", get(services::proof::list_proofs))
        .route("/proof/:proof_id/certificate", get(services::proof::get_certificate))
        .route("/proof/:proof_id/verify", get(services::proof::verify_proof))
        .route("/proof/certificate-sign", post(services::proof::certificate_sign))
        .route("/proof/certificate-verify", post(services::proof::verify_certificate_sig))
        .route("/proof/public-key", get(services::proof::public_key))
        .route("/proof/scitt-receipt/:cid", get(services::proof::scitt_receipt))
        // E1.7-E1.8 / E6.6-E6.7: W3C VC 2.0, SCITT verify, PDF certificate
        .route("/proof/vc/:agent_pid", post(services::proof::issue_vc))
        .route("/proof/scitt/verify", post(services::proof::scitt_verify))
        .route("/proof/merkle-proof/:cid", get(services::proof::merkle_proof))
        .route("/proof/:proof_id/certificate.pdf", get(services::proof::certificate_pdf))
        .route("/proof/trust-trend/:pid", get(services::proof::trust_trend_by_pid))

        // ── Service 4: Long Memory ───────────────────────────
        .route("/memory/plane/overview", get(services::memory_plane::overview))
        .route("/memory/plane/context-efficiency", get(services::memory_plane::context_efficiency))
        .route("/memory/write", post(services::memory::write_memory))
        // Fix-3: canonical recall/query/interference now serve the memory2 (full-feature) handlers.
        // The old handlers (memory::recall_memory etc.) are still compiled but are no longer
        // the canonical path — they are served as deprecated aliases merged below.
        .route("/memory/recall/:namespace", get(services::memory2::recall_full))
        .route("/memory/knowledge/ingest", post(services::memory::knowledge_ingest))
        .route(
            "/memory/knowledge/pipeline/spec",
            get(services::knowledge_pipeline::get_pipeline_spec),
        )
        .route("/memory/knowledge/query", post(services::memory2::knowledge_query_full))
        .route("/memory/interference/:agent_pid", get(services::memory2::interference_real))
        .route("/memory/agents", get(services::memory::list_agents))
        .route("/memory/stale-analysis", get(services::memory::stale_analysis))
        .route("/memory/optimize-context/:agent_pid", post(services::memory::optimize_context))
        .route("/memory/context-pressure/:agent_pid", get(services::memory::context_pressure))
        .route("/memory/region/configure", post(services::memory::region_configure))
        .route("/memory/region/:agent_pid", get(services::memory::region_view))
        .route("/memory/eviction-policy", post(services::memory::eviction_policy))
        .route("/memory/tier/change", post(services::memory::tier_change))
        .route("/memory/tier/distribution/:agent_pid", get(services::memory::tier_distribution))
        // E2.1-E2.4: Semantic search, consolidation, temporal decay, cross-agent share
        .route("/memory/semantic-search", get(services::memory::semantic_search))
        .route("/memory/consolidate/:agent_pid", post(services::memory::consolidate))
        .route("/memory/stale/:agent_pid", get(services::memory::stale_packets))
        .route("/memory/share", post(services::memory::share_memory))
        .route("/memory/enrich/:agent_pid", post(services::memory::enrich_memory))

        // ── Service 5: Reliability Monitor ───────────────────
        .route("/monitor/health", get(services::monitor::health_check))
        .route("/monitor/trust", get(services::monitor::trust_live))
        .route("/monitor/integrity", get(services::monitor::integrity_check))
        .route("/monitor/alerts", get(services::monitor::alert_rules))
        .route("/monitor/alert-rules", post(services::monitor::create_alert_rule))
        .route("/monitor/cost-dashboard", get(services::monitor::cost_dashboard))
        .route("/monitor/cost-center", get(services::monitor::cost_center))
        .route("/monitor/trust-trend", get(services::monitor::trust_trend))
        .route("/history/regression-detect", get(services::history::regression_detect_fleet))
        .route("/monitor/storage/layout", get(services::monitor::storage_layout))
        .route("/monitor/storage/zones/:zone_name", get(services::monitor::storage_zone_health))
        .route("/monitor/budget-alerts", get(services::monitor::budget_alerts))
        .route("/monitor/anomalies", get(services::monitor::anomaly_detection))
        .route("/monitor/usage-export", get(services::monitor::usage_export))
        // E3.10: SLO tracking + error budget
        .route("/monitor/slos", post(services::monitor::create_slo).get(services::monitor::list_slos))
        .route("/monitor/slos/:slo_id/report", get(services::monitor::slo_report))
        // E4.4-E4.6: Anomaly detection v2, capacity forecast, Grafana export
        .route("/monitor/anomalies/v2", get(services::monitor::anomaly_detection_v2))
        .route("/monitor/forecast", get(services::monitor::capacity_forecast))
        .route("/monitor/grafana-dashboard", get(services::monitor::grafana_dashboard))
        .route("/monitor/tools", get(services::monitor::tools_health))
        .route("/monitor/signals", get(services::monitor::signals_log))
        .route("/monitor/cgroups", get(services::monitor::cgroups_report))
        .route(
            "/monitor/native",
            get(services::observability::native_dashboard),
        )
        .route(
            "/monitor/native/charts",
            get(services::observability::native_charts),
        )
        .route(
            "/monitor/native/charts/pin",
            post(services::observability::set_native_chart_pin),
        )
        // TC-4: Boundary probe detection — per-agent probe scores + recommended action
        .route("/monitor/probe-scores", get(services::monitor::anomalies))
        .route("/gateway/status", get(services::gateway::gateway_status))

        // ── Runtime Control: mode + pilots ────────────────────
        .route("/runtime/mode", get(services::runtime_control::get_runtime_mode).post(services::runtime_control::set_runtime_mode))
        .route("/runtime/activation", get(services::runtime_control::get_activation_status).post(services::runtime_control::activate_node))
        .route("/runtime/policy", get(services::runtime_control::get_runtime_policy).post(services::runtime_control::update_runtime_policy))
        .route("/runtime/backends", get(crate::substrate::cvr::api::get_backends))
        .route("/runtime/deploy-verify", get(crate::substrate::cvr::api::get_deploy_verify))
        .route("/runtime/agentgateway", get(crate::substrate::agentgateway::get_status))
        .route(
            "/runtime/agentgateway/ext-auth",
            post(crate::substrate::agentgateway::post_ext_auth),
        )
        .route("/runtime/ecosystem", get(crate::substrate::cvr::api::get_ecosystem))
        .route("/runtime/explain/:receipt_id", get(crate::substrate::cvr::api::get_explain))
        .route("/runtime/cease-proof/:agent_pid", get(crate::substrate::cvr::api::get_cease_proof))
        .route("/runtime/enforcement", get(services::runtime_enforcement::get_runtime_enforcement))
        .route("/runtime/enforcement/:sandbox_id", get(services::runtime_enforcement::get_runtime_enforcement_detail))
        .route("/runtime/lab-mode", get(services::settings_llms::get_lab_mode))
        .route(
            "/runtime/enable-hardening",
            post(services::settings_llms::enable_hardening),
        )
        .route(
            "/runtime/intelligence-posture",
            get(services::settings_llms::get_intelligence_posture),
        )
        .route(
            "/runtime/pores",
            get(services::settings_llms::get_landlock_pores),
        )
        .route(
            "/runtime/llm-vendor-cut",
            get(services::settings_llms::get_llm_vendor_cut),
        )
        .route(
            "/runtime/security-profile",
            get(crate::substrate::workload_profile::get_profile)
                .post(crate::substrate::workload_profile::set_profile),
        )
        .route(
            "/runtime/security-profiles",
            get(crate::substrate::workload_profile::list_profiles),
        )
        .route(
            "/node/contract",
            get(crate::substrate::node_contract::get_node_contract),
        )
        // Talk LLM link — these handlers existed but were never mounted, so
        // Connect LLM posted into the SPA fallback (405) and never stored a key.
        .route(
            "/settings/llms/status",
            get(services::settings_llms::get_llm_link_status),
        )
        .route(
            "/settings/llms/providers",
            get(services::settings_llms::get_llm_providers)
                .post(services::settings_llms::set_llm_providers),
        )
        .route("/settings/llms/link", post(services::settings_llms::link_llm))
        .route(
            "/settings/llms/fallback-cap",
            get(services::settings_llms::get_llm_fallback_cap),
        )
        .route(
            "/settings/llms/routing-rules",
            get(services::settings_llms::get_llm_routing_rules)
                .post(services::settings_llms::set_llm_routing_rules),
        )
        .route(
            "/settings/llms/overrides",
            get(services::settings_llms::get_llm_overrides)
                .post(services::settings_llms::set_llm_overrides),
        )
        .route(
            "/settings/llms/charts",
            get(services::settings_llms::get_llm_charts),
        )
        .route(
            "/settings/llms/guardrails",
            get(services::settings_llms::get_llm_guardrails)
                .post(services::settings_llms::set_llm_guardrails),
        )
        .route(
            "/settings/llms/privacy-tags",
            get(services::settings_llms::get_llm_privacy_tags)
                .post(services::settings_llms::set_llm_privacy_tags),
        )
        .route("/runtime/self", get(services::iia_runtime::get_runtime_self))
        .route("/runtime/matrix", get(services::iia_runtime::get_runtime_matrix))
        .route("/runtime/fleet/charter", get(services::iia_runtime::get_fleet_charter))
        .route(
            "/runtime/contract",
            get(services::iia_runtime::get_runtime_contract),
        )
        .route(
            "/runtime/hardware",
            get(services::iia_runtime::get_runtime_hardware),
        )
        .route(
            "/runtime/permissions",
            get(services::iia_runtime::get_runtime_permissions),
        )
        .route(
            "/runtime/provenance",
            get(services::iia_runtime::get_runtime_provenance),
        )
        .route(
            "/runtime/delegate",
            post(services::iia_runtime::post_runtime_delegate),
        )
        .route(
            "/runtime/continuity/evaluate",
            post(services::iia_runtime::post_continuity_evaluate),
        )
        .route(
            "/runtime/export",
            get(services::iia_runtime::get_runtime_export),
        )
        .route("/n4/hello", post(services::iia_runtime::post_n4_hello))
        .route("/n4/qualify", post(services::iia_runtime::post_n4_qualify))
        .route("/n4/cognize", post(services::iia_runtime::post_n4_cognize))
        .route("/qpr/intent", post(services::iia_runtime::post_qpr_intent))
        .route("/runtime/acs/:pid", get(services::acs::get_acs))
        .route("/runtime/cage/:pid", get(services::acs::get_cage))
        .route("/runtime/nsfs/:pid", get(services::acs::get_nsfs))
        .route("/runtime/nsfs/:pid/ensure", post(services::acs::ensure_nsfs))
        .route("/substrate/status", get(crate::substrate::status::get_substrate_status))
        .route(
            "/substrate/admission/matrix",
            get(crate::substrate::admission_status::get_admission_matrix),
        )
        // ── CNKTROS native runtime (Phase-1/2 substrate; under /api/v1/native) ──
        .route(
            "/native/software/bind",
            post(crate::substrate::origin_binding::post_bind_software),
        )
        .route(
            "/native/workloads",
            post(crate::substrate::origin_binding::post_register_workload),
        )
        .route(
            "/native/intelligence",
            post(crate::substrate::origin_binding::post_register_intelligence),
        )
        .route(
            "/native/software/:id",
            get(crate::substrate::origin_binding::get_software_status),
        )
        .route(
            "/native/compat/agent/:agent_pid",
            get(crate::substrate::origin_binding::get_compat_agent),
        )
        .route(
            "/native/channels/observe",
            post(crate::substrate::channel_surface::post_observe_channel),
        )
        .route(
            "/native/channels",
            get(crate::substrate::target_catalog::get_channels),
        )
        .route(
            "/native/surfaces",
            get(crate::substrate::target_catalog::get_surfaces),
        )
        .route(
            "/native/surfaces/watch",
            get(crate::substrate::target_catalog::get_catalog_watch),
        )
        .route(
            "/native/surfaces/:id/resolve",
            post(crate::substrate::channel_surface::post_resolve_surface),
        )
        .route(
            "/native/surfaces/:id/probe",
            post(crate::substrate::target_catalog::post_probe_surface),
        )
        .route(
            "/native/invocations",
            post(crate::substrate::channel_surface::post_invocation),
        )
        .route(
            "/native/receipts/:operation_id",
            get(crate::substrate::channel_surface::get_receipt_handler),
        )
        .route(
            "/native/evidence/graph",
            get(crate::substrate::channel_surface::get_evidence_graph),
        )
        .route(
            "/native/inference/project",
            post(crate::substrate::contract_projection::http_project),
        )
        .route(
            "/native/proxy/routes",
            post(crate::substrate::proxy_plane::post_put_route),
        )
        .route(
            "/native/proxy/execute",
            post(crate::substrate::proxy_plane::post_execute),
        )
        .route(
            "/substrate/crash-recovery",
            get(crate::substrate::crash_recovery::get_posture),
        )
        .route(
            "/substrate/crash-recovery/reconcile-unknown",
            post(crate::substrate::crash_recovery::post_reconcile_unknown),
        )
        .route(
            "/substrate/runtime-invariants",
            get(crate::substrate::runtime_invariants::get_catalog),
        )
        .route(
            "/support/bundle",
            get(crate::services::support_bundle::get_support_bundle),
        )
        .route("/cvr/status", get(crate::substrate::cvr::api::get_cvr_status))
        .route(
            "/cvr/microd",
            get(crate::substrate::cvr::api::get_microd_status),
        )
        .route(
            "/cvr/microd/warm",
            post(crate::substrate::cvr::api::post_microd_warm),
        )
        .route(
            "/product/promise",
            get(crate::substrate::proof_export_api::get_product_promise),
        )
        .route(
            "/proof/export/:agent_pid",
            get(crate::substrate::proof_export_api::get_proof_export),
        )
        .route(
            "/arc/posture",
            get(crate::substrate::arc::api::get_arc_posture),
        )
        .route(
            "/arc/:agent_pid/graph",
            get(crate::substrate::arc::api::get_arc_graph),
        )
        .route(
            "/arc/:agent_pid/query",
            get(crate::substrate::arc::api::get_arc_query),
        )
        .route(
            "/agent-memory/posture",
            get(crate::substrate::agent_memory::api::get_posture),
        )
        .route(
            "/agent-memory/capsule/:agent_vid",
            get(crate::substrate::agent_memory::api::get_capsule),
        )
        .route(
            "/forensics/moment/:moment_id/proof",
            get(crate::substrate::agent_memory::api::get_moment_proof),
        )
        .route(
            "/svf/posture",
            get(crate::substrate::svf::api::get_posture),
        )
        .route(
            "/svf/objects/:agent_vid",
            get(crate::substrate::svf::api::get_objects),
        )
        .route(
            "/svf/expand",
            axum::routing::post(crate::substrate::svf::api::post_expand),
        )
        .route(
            "/svf/grants",
            axum::routing::post(crate::substrate::svf::api::post_grant),
        )
        .route(
            "/svf/grants/:agent_vid",
            get(crate::substrate::svf::api::get_grants),
        )
        .route(
            "/svf/tools/stubs/:agent_vid",
            get(crate::substrate::svf::api::get_tool_stubs),
        )
        .route(
            "/svf/resolve",
            axum::routing::post(crate::substrate::svf::api::post_resolve),
        )
        .route(
            "/svf/materialize",
            axum::routing::post(crate::substrate::svf::api::post_materialize),
        )
        .route(
            "/svf/relations",
            axum::routing::post(crate::substrate::svf::api::post_relation),
        )
        .route(
            "/svf/relations/:agent_vid/:object_id",
            get(crate::substrate::svf::api::get_relations),
        )
        .route(
            "/svf/derived",
            axum::routing::post(crate::substrate::svf::api::post_derived),
        )
        .route(
            "/svf/derived/:agent_vid",
            get(crate::substrate::svf::api::get_derived),
        )
        .route(
            "/svf/fade/sync/:agent_vid",
            axum::routing::post(crate::substrate::svf::api::post_fade_sync),
        )
        .route(
            "/svf/receipts/:agent_vid",
            get(crate::substrate::svf::api::get_receipts),
        )
        .route(
            "/dal/posture",
            get(crate::substrate::dal_api::get_posture),
        )
        .route(
            "/workbench/posture",
            get(services::workbench::get_posture),
        )
        .route(
            "/dal/start",
            axum::routing::post(crate::substrate::dal_api::post_start),
        )
        .route(
            "/dal/:run_id",
            get(crate::substrate::dal_api::get_run),
        )
        .route(
            "/dal/:run_id/turn",
            axum::routing::post(crate::substrate::dal_api::post_turn),
        )
        .route(
            "/rollup/posture",
            get(crate::substrate::agent_memory::rollup::api::get_posture),
        )
        .route(
            "/rollup/:agent_vid/metrics",
            get(crate::substrate::agent_memory::rollup::api::get_metrics),
        )
        .route(
            "/rollup/:agent_vid/policy",
            get(crate::substrate::agent_memory::rollup::api::get_policy)
                .put(crate::substrate::agent_memory::rollup::api::put_policy),
        )
        .route(
            "/rollup/:agent_vid/explain/:evidence_id",
            get(crate::substrate::agent_memory::rollup::api::get_explain),
        )
        .route(
            "/rollup/:agent_vid/aging-pass",
            axum::routing::post(crate::substrate::agent_memory::rollup::api::post_aging_pass),
        )
        .route(
            "/rollup/:agent_vid/scheduled-pass",
            axum::routing::post(crate::substrate::agent_memory::rollup::api::post_scheduled_pass),
        )
        .route(
            "/rollup/:agent_vid/rehydrate/:evidence_id",
            axum::routing::post(crate::substrate::agent_memory::rollup::api::post_rehydrate),
        )
        .route(
            "/rollup/:agent_vid/lock/:evidence_id",
            axum::routing::post(crate::substrate::agent_memory::rollup::api::post_lock),
        )
        .route(
            "/rollup/tombstone/:evidence_id",
            get(crate::substrate::agent_memory::rollup::api::get_tombstone),
        )
        .route(
            "/rollup/demo/c0c10",
            axum::routing::post(crate::substrate::agent_memory::rollup::api::post_c0c10_demo),
        )
        .route(
            "/forensics/moments/:agent_vid",
            get(crate::substrate::agent_memory::rollup::api::list_moments),
        )
        .route("/dim/:agent_pid", get(crate::substrate::dim::api::get_dim))
        .route(
            "/dim/:agent_pid/refresh",
            post(crate::substrate::dim::api::post_dim_refresh),
        )
        .route(
            "/dim/:agent_pid/regulate",
            post(crate::substrate::dim::api::post_dim_regulate),
        )
        .route(
            "/dim/:agent_pid/poison",
            post(crate::substrate::dim::api::post_dim_poison),
        )
        .route(
            "/dim/:agent_pid/journal",
            get(crate::substrate::dim::api::get_dim_journal),
        )
        .route(
            "/dim/:agent_pid/wake/evaluate",
            post(crate::substrate::dim::api::post_dim_wake_evaluate),
        )
        .route(
            "/dim/:agent_pid/wake",
            get(crate::substrate::dim::api::get_dim_wake_pending),
        )
        .route(
            "/dim/:agent_pid/wake/consume",
            post(crate::substrate::dim::api::post_dim_wake_consume),
        )
        .route(
            "/memory/retrieve/:agent_pid",
            get(crate::substrate::memory_retrieval_api::get_memory_retrieve),
        )
        .route(
            "/range/status",
            get(crate::substrate::crk::api::get_status),
        )
        .route(
            "/range/window",
            post(crate::substrate::crk::api::post_window),
        )
        .route(
            "/range/observe",
            post(crate::substrate::crk::api::post_observe),
        )
        .route(
            "/range/commit",
            post(crate::substrate::crk::api::post_commit_procedure),
        )
        .route(
            "/range/relate",
            post(crate::substrate::crk::api::post_relate),
        )
        .route(
            "/range/search",
            post(crate::substrate::crk::api::post_search),
        )
        .route(
            "/range/replay/:manifest_id",
            get(crate::substrate::crk::api::get_replay),
        )
        .route(
            "/range/rollup",
            post(crate::substrate::crk::api::post_rollup),
        )
        .route(
            "/range/demo/rangeguard",
            post(crate::substrate::crk::api::post_demo_rangeguard),
        )
        .route(
            "/knot/:agent_pid/interference/scan",
            post(crate::substrate::memory_retrieval_api::post_interference_scan),
        )
        .route(
            "/knot/:agent_pid/interference",
            get(crate::substrate::memory_retrieval_api::get_interference),
        )
        .route(
            "/knot/:agent_pid/foresight",
            get(crate::substrate::memory_retrieval_api::get_foresight),
        )
        .route(
            "/knowledge/:agent_pid/boundary",
            get(crate::substrate::knowledge_boundary_api::get_boundary)
                .put(crate::substrate::knowledge_boundary_api::put_boundary),
        )
        .route(
            "/knowledge/:agent_pid/classify",
            post(crate::substrate::knowledge_boundary_api::post_classify),
        )
        .route(
            "/knowledge/:agent_pid/assert-justify",
            post(crate::substrate::knowledge_boundary_api::post_assert_justify),
        )
        .route(
            "/knowledge/:agent_pid/harden-default",
            post(crate::substrate::knowledge_boundary_api::post_harden_default),
        )
        .route(
            "/operator/pulse",
            get(crate::operator::pulse::get_operator_pulse),
        )
        .route(
            "/operator/fix/queue",
            get(crate::operator::fix_queue::get_operator_fix_queue),
        )
        .route(
            "/operator/watch/events",
            get(crate::operator::watch_events::get_operator_watch_events),
        )
        .route(
            "/kernel/address-dac",
            get(crate::kernel::address_dac_api::get_address_dac_index),
        )
        .route(
            "/kernel/address-dac/contract",
            get(crate::kernel::address_dac_api::get_address_dac_contract),
        )
        .route(
            "/kernel/address-dac/rules",
            axum::routing::put(crate::kernel::address_dac_api::put_address_dac_rules),
        )
        .route(
            "/kernel/address-dac/hitl",
            axum::routing::put(crate::kernel::address_dac_api::put_address_dac_hitl),
        )
        .route(
            "/kernel/address-dac/simulate",
            post(crate::kernel::address_dac_api::post_address_dac_simulate),
        )
        .route(
            "/kernel/address-dac/unseal",
            post(crate::kernel::address_dac_api::post_address_dac_unseal),
        )
        .route(
            "/kernel/identity-stack",
            get(crate::kernel::address_dac_api::get_identity_stack),
        )
        .route(
            "/kernel/agent-explain",
            get(crate::kernel::agent_explain::get_agent_explain),
        )
        .route("/kernel/aios/claim-readiness", get(services::aios::claim_readiness))
        .route("/kernel/aios/modules", get(services::aios::modules))
        .route("/kernel/aios/fleet", get(services::aios::fleet))
        .route("/kernel/aios/operate", post(services::aios::operate))
        .route("/kernel/aios/syscall", post(services::aios::syscall))
        .route("/intelligence/spec-schema", get(services::intelligence_quick::get_spec_schema))
        .route("/intelligence/apply", post(services::intelligence_quick::apply_intelligence))
        .route(
            "/intelligence/:pid/pack",
            get(services::intelligence_quick::get_intelligence_pack),
        )
        .route(
            "/intelligence/gateway/status",
            get(services::world_gateway::gateway_status),
        )
        .route(
            "/intelligence/gateway/root",
            post(services::world_gateway::set_root),
        )
        .route(
            "/intelligence/gateway/address",
            post(services::world_gateway::put_address),
        )
        .route(
            "/intelligence/gateway/addresses",
            get(services::world_gateway::list_addresses),
        )
        .route(
            "/intelligence/gateway/grant",
            post(services::world_gateway::put_grant),
        )
        .route(
            "/intelligence/gateway/grants",
            get(services::world_gateway::list_grants),
        )
        .route(
            "/intelligence/gateway/grant/revoke",
            post(services::world_gateway::revoke_grant),
        )
        .route(
            "/world/browser",
            get(services::browser_explorer::status),
        )
        .route(
            "/world/browser/navigate",
            post(services::browser_explorer::navigate),
        )
        .route(
            "/intelligence/gateway/browser/navigate",
            post(services::browser_explorer::navigate),
        )
        .route(
            "/world/browser/sessions",
            get(services::browser_explorer::list_sessions),
        )
        .route(
            "/world/browser/sessions/:id",
            get(services::browser_explorer::get_session),
        )
        .route("/protocol/world", get(services::conp_protocol::world_connect))
        .route("/protocol/conp/info", get(services::conp_protocol::conp_info))
        .route(
            "/protocol/conp/capabilities",
            get(services::conp_protocol::conp_capabilities),
        )
        .route(
            "/protocol/conp/command",
            post(services::conp_protocol::conp_command),
        )
        .route(
            "/protocol/conp/message",
            post(services::conp_protocol::conp_message),
        )
        .route(
            "/protocol/conp/estop",
            post(services::conp_protocol::conp_estop),
        )
        .route(
            "/protocol/conp/safety/estop",
            post(services::conp_protocol::conp_estop),
        )
        .route("/forensics/status", get(services::forensics::get_forensics_status))
        .route("/forensics/package", get(services::forensics::get_forensics_package))
        .route(
            "/forensics/court-readiness",
            get(services::forensics::get_court_readiness),
        )
        .route("/soas/report", get(services::soas::get_soas_report))
        .route("/soas/report/pdf", get(services::soas::get_soas_report_pdf))
        .route("/aacr/mint", post(services::aacr::mint_aacr))
        .route("/aacr/latest", get(services::aacr::latest_aacr))
        .route("/aacr/chain", get(services::aacr::chain_aacr))
        .route("/aacr/report", get(services::aacr::report_aacr))
        .route("/aacr/report/pdf", get(services::aacr::report_aacr_pdf))
        .route("/aacr/verify", post(services::aacr::verify_aacr))
        .route("/aipsprt/schema", get(services::aipsprt_api::schema))
        .route("/aipsprt/verify", post(services::aipsprt_api::verify_passport))
        .route("/aipsprt/outbox", get(services::aipsprt_api::get_outbox))
        .route(
            "/aipsprt/index/digest/:digest",
            get(services::aipsprt_api::index_by_digest),
        )
        .route(
            "/aipsprt/private/:passport_id",
            get(services::aipsprt_api::get_private),
        )
        .route(
            "/aipsprt/:passport_id/c2pa-map",
            get(services::aipsprt_api::c2pa_map),
        )
        .route(
            "/aipsprt/:passport_id",
            get(services::aipsprt_api::get_passport),
        )
        .route(
            "/spend/ceiling/:pid",
            get(services::aipsprt_api::spend_ceiling),
        )
        .route(
            "/spend/burn/:pid",
            get(services::aipsprt_api::spend_burn),
        )
        .route(
            "/spend/cease/latest/:pid",
            get(services::aipsprt_api::spend_cease_latest),
        )
        .route("/forensics/chain", get(services::forensics::get_forensics_chain))
        .route("/forensics/rollups", get(services::forensics::get_forensics_rollups))
        .route("/context/status", get(services::context::context_status))
        .route("/topology/center", get(services::topology_center::get_topology_center))
        .route("/cnp/overview", get(services::cnp_surface::get_cnp_overview))
        .route("/cnp/wire", get(services::cnp_surface::get_cnp_wire))
        .route("/cnp/inbox", get(services::cnp_surface::get_cnp_inbox))
        .route("/cnp/send", post(services::cnp_surface::post_cnp_send))
        .route("/cnp/actuation", post(services::cnp_surface::post_cnp_actuation))
        .route("/cnp/messages", post(services::cnp_surface::post_cnp_messages))
        .route(
            "/missions",
            post(services::missions::create_mission),
        )
        .route(
            "/missions/:id",
            get(services::missions::get_mission),
        )
        .route(
            "/missions/:id/resume",
            get(services::missions::resume_mission),
        )
        .route(
            "/missions/:id/steps",
            post(services::missions::append_step),
        )
        .route(
            "/missions/:id/complete",
            post(services::missions::complete_mission),
        )
        .route(
            "/missions/:id/cancel",
            post(services::missions::cancel_mission),
        )
        .route(
            "/command-center/snapshot",
            get(services::command_center::snapshot),
        )
        .route("/reports/center", get(services::report_center::get_report_center))
        .route("/reports/center/receipts/:receipt_id", get(services::report_center::get_report_receipt))
        .route("/admin/pilots", get(services::runtime_control::list_pilots).post(services::runtime_control::create_pilot))
        .route("/admin/pilots/:pilot_id", delete(services::runtime_control::revoke_pilot))
        .route("/admin/pilots/:pilot_id/extend", post(services::runtime_control::extend_pilot))
        .route("/admin/pilots/:pilot_id/scope", post(services::runtime_control::update_pilot_scope))

        // ── Service 6: Agent History ─────────────────────────
        .route("/history/agents", get(services::history::list_agents))
        .route("/history/agents/:agent_pid/timeline", get(services::history::agent_timeline))
        .route("/history/agents/:agent_pid/sessions", get(services::history::agent_sessions))
        .route("/history/audit", get(services::history::full_audit))
        .route("/history/agents/:agent_pid/regression", get(services::history::regression_detect))
        .route("/history/agents/:agent_pid/diff", get(services::history::agent_diff))
        .route("/history/replay", post(services::history::replay))
        .route("/history/agents/:agent_pid/sessions-range", get(services::history::sessions_range))
        // E5.8-E5.10: Cost timeline, fleet compare, behaviour drift
        .route("/history/agents/:agent_pid/cost-timeline", get(services::history::cost_timeline))
        .route("/history/fleet/compare", get(services::history::fleet_compare))
        .route("/history/agents/:agent_pid/drift", get(services::history::behaviour_drift))
        // E6.10: Terminated agent archive
        .route("/history/agents/archive", get(services::history::agent_archive))
        .route("/history/agents/:agent_pid/terminate", post(services::history::terminate_agent))

        // ── Service 7: Multi-Agent Debugger ──────────────────
        .route("/multiagent/pipeline", post(services::multiagent::run_pipeline))
        .route("/multiagent/trace/:pipe_name", get(services::multiagent::pipeline_trace))
        .route("/multiagent/map", get(services::multiagent::cross_agent_map))
        .route(
            "/multiagent/mesh/knowledge-plane",
            get(services::mesh_knowledge_plane::get_mesh_knowledge_plane),
        )
        .route("/multiagent/grant", post(services::multiagent::grant_access))
        .route("/multiagent/revoke", post(services::multiagent::revoke_access))
        .route("/multiagent/tasks/dispatch", post(services::multiagent::dispatch_task))
        .route("/multiagent/ports", get(services::multiagent::list_ports))
        // E3.1: HITL approval gate
        .route("/multiagent/pipelines/:pipeline_id/approve-step/:step", post(services::multiagent::approve_step))

        // ── Service 8: AI Decision Log for Disputes ──────────
        .route("/disputes/record", post(services::disputes::record_decision))
        .route("/disputes/decisions", get(services::disputes::list_decisions))
        .route("/disputes/:decision_id/report", get(services::disputes::generate_dispute_report))
        .route("/disputes/provenance/:cid", get(services::disputes::provenance_chain))
        .route("/disputes/judgment", post(services::disputes::judgment))
        .route("/disputes/risk-check", post(services::disputes::risk_check))
        .route("/disputes/:decision_id/defense-package", get(services::disputes::defense_package))
        .route("/disputes/regulation-template/:framework", get(services::disputes::regulation_template))
        // E1.9-E1.10 / E6.8-E6.9: Evidence package + immutable decision record v2
        .route("/disputes/:decision_id/export-package", post(services::disputes::export_package))
        .route("/disputes/record-decision-v2", post(services::disputes::record_decision_v2))
        // E3.8-E3.9: Regulations report + GDPR Art.22 scan
        .route("/disputes/regulations-report", post(services::disputes::regulations_report))
        .route("/disputes/scan-gdpr-art22", post(services::disputes::scan_gdpr_art22))
        // Adaptive LLM Router
        .route("/adaptive/status",                    get(services::adaptive::adaptive_status))
        .route("/adaptive/decisions",                 get(services::adaptive::adaptive_decisions))
        .route("/adaptive/agents/:pid/config",        get(services::adaptive::adaptive_agent_config))
        .route("/adaptive/agents/:pid/config",        axum::routing::put(services::adaptive::adaptive_set_config))
        // Knowledge Transfer Graph
        .route("/knowledge-graph",                    get(services::knowledge_transfer::get_graph))
        .route("/knowledge-graph/agents/:pid",        get(services::knowledge_transfer::get_agent_node))
        .route("/knowledge-graph/transfers",          get(services::knowledge_transfer::get_transfers))
        .route("/knowledge-graph/transfer",           post(services::knowledge_transfer::trigger_transfer))

        // ── Service 9: Pipeline Confirmation ─────────────────
        .route("/pipeline/:pipeline_id/steps", get(services::pipeline::pipeline_steps))
        .route("/pipeline/:pipeline_id/integrity", get(services::pipeline::pipeline_integrity))
        .route("/pipeline/:pipeline_id/cid-chain", get(services::pipeline::pipeline_cid_chain))
        .route("/pipeline/:pipeline_id/gate", get(services::pipeline::pipeline_gate))
        .route("/pipeline/pre-deploy-diff", post(services::pipeline::pre_deploy_diff))
        .route("/pipeline/definitions", post(services::pipeline::create_definition).get(services::pipeline::list_definitions))
        .route("/pipeline/definitions/:def_id/validate-run/:run_id", get(services::pipeline::validate_run))
        .route("/pipeline/:pipeline_id/artifacts", post(services::pipeline::record_artifact).get(services::pipeline::list_artifacts))
        .route("/pipeline/:pipeline_id/replay-from-step/:step_n", post(services::pipeline::replay_from_step))
        .route("/pipeline/gate-policies", post(services::pipeline::create_gate_policy).get(services::pipeline::list_gate_policies))
        // S11: KECS auto-suspend sweep
        .route("/pipeline/kecs-suspend-sweep", post(services::pipeline::kecs_suspend_sweep))

        // T8 — apps catalog + workflow catalog mounts
        .route("/apps", get(services::apps_catalog::list_apps))
        .route(
            "/apps/parity",
            get(services::apps_catalog::catalog_parity_status),
        )
        .route("/apps/:id", get(services::apps_catalog::show_app))
        .route(
            "/workflows/catalog",
            get(services::workflow_catalog_sync::get_workflow_catalog_status),
        )
        .route(
            "/workflows/catalog/sync",
            post(services::workflow_catalog_sync::post_workflow_catalog_sync),
        )

        // ── Service 10: Experiment Tracking ──────────────────
        .route("/experiments", get(services::experiments::list_experiments))
        .route("/experiments/create", post(services::experiments::create_experiment))
        .route("/experiments/run", post(services::experiments::run_experiment))
        .route("/experiments/:experiment_id/runs", get(services::experiments::experiment_runs))
        .route("/experiments/:experiment_id/compare", post(services::experiments::compare_runs))
        .route("/experiments/:experiment_id/winner", get(services::experiments::experiment_winner))
        .route("/experiments/:experiment_id/significance", get(services::experiments::experiment_significance))
        .route("/experiments/:experiment_id/suggest", get(services::experiments::experiment_suggest))
        .route("/experiments/:experiment_id/compare-cost", get(services::experiments::compare_cost))
        // E2.9-E2.12: Judge eval, golden datasets, significance test, auto-promote
        .route("/experiments/:experiment_id/eval-summary", get(services::experiments::eval_summary))
        .route("/experiments/datasets", post(services::experiments::create_dataset).get(services::experiments::list_datasets))
        .route("/experiments/:experiment_id/significance-test", get(services::experiments::significance_test))
        .route("/experiments/:experiment_id/auto-promote", axum::routing::patch(services::experiments::auto_promote))

        // ── Service 11 (new): Prompt Registry (Moat 3) ─────
        .route("/prompts", get(services::prompts::list_prompts).post(services::prompts::create_prompt))
        .route("/prompts/:id", get(services::prompts::get_prompt).delete(services::prompts::delete_prompt))
        .route("/prompts/:id/versions", get(services::prompts::list_versions).post(services::prompts::add_version))
        .route("/prompts/:id/versions/:ver/approve", post(services::prompts::approve_version))
        .route("/prompts/:id/activate", post(services::prompts::activate_version).patch(services::prompts::activate_with_rollback))
        .route("/prompts/:id/resolve", get(services::prompts::resolve_prompt))
        // E2.5-E2.8: Template render, rollback-activate, lint, analytics
        .route("/prompts/:id/render", post(services::prompts::render_prompt))
        .route("/prompts/:id/lint", post(services::prompts::lint_prompt))
        .route("/prompts/:id/analytics", get(services::prompts::prompt_analytics))

        // ── Service 12 (prev 11): Tool Execution (Track 3) ─────
        .route("/tools/mcp/register", post(services::tools::mcp_register))
        .route("/tools/mcp/invoke", post(services::tools::mcp_invoke))
        .route("/tools/mcp/bridges", get(services::tools::mcp_bridges))
        .route("/tools/mcp/bridges/:bridge_id", delete(services::tools::mcp_unregister))
        .route("/tools/approvals/pending", get(services::tools::approvals_pending))
        .route("/tools/approvals/:audit_id", post(services::tools::approve_tool))
        .route(
            "/tools/approvals/:audit_id/deny",
            post(services::tools::deny_tool),
        )
        .route("/tools/signals/send", post(services::tools::send_signal))
        .route("/tools/agents/:agent_pid/did", get(services::tools::agent_did))
        .route("/tools/agents/:agent_pid/card", get(services::tools::agent_card))
        // E4.7-E4.9: Scoped bindings, circuit breaker, collision check
        .route("/tools/bindings/scoped", post(services::tools::bind_tool_scoped))
        .route("/tools/mcp/invoke-scoped", post(services::tools::mcp_invoke_scoped))
        .route("/tools/mcp/collision-check", get(services::tools::tool_collision_check))
        .route("/tools/bridges/:bridge_id/circuit-breaker", post(services::tools::configure_circuit_breaker).get(services::tools::circuit_breaker_status))
        .route("/tools/signals/handlers", post(services::tools::register_signal_handler).get(services::tools::list_signal_handlers))
        .route("/tools/a2a/open", post(services::tools::a2a_open))
        .route("/tools/a2a/:channel_id/send", post(services::tools::a2a_send))
        .route("/tools/cgroups", post(services::tools::register_cgroup).get(services::tools::list_cgroups))
        // Plugin .cpkg install + hub workflow publish (honesty stub)
        .route(
            "/plugins/cpkg/preflight",
            post(services::plugin_cpkg::post_cpkg_preflight),
        )
        .route(
            "/plugins/cpkg/install",
            post(services::plugin_cpkg::post_cpkg_install),
        )
        .route(
            "/plugins/cpkg/bundle/export",
            post(services::plugin_cpkg::post_cpkg_bundle_export),
        )
        .route(
            "/plugins/cpkg/bundle/import",
            post(services::plugin_cpkg::post_cpkg_bundle_import),
        )
        // ExtensionHost / plugin lifecycle (was orphaned from router)
        .route(
            "/plugins/lifecycle",
            get(services::plugin_lifecycle::list_plugin_lifecycle),
        )
        .route(
            "/plugins/:id/lifecycle",
            get(services::plugin_lifecycle::get_plugin_lifecycle)
                .post(services::plugin_lifecycle::apply_plugin_lifecycle),
        )
        .route(
            "/plugins/:id/lifecycle/history",
            get(services::plugin_lifecycle::get_plugin_lifecycle_history),
        )
        .route(
            "/native/extensions",
            get(services::extension_host::list_extensions_handler),
        )
        .route(
            "/native/extensions/:id",
            get(services::extension_host::get_extension),
        )
        .route(
            "/native/extensions/:id/actions",
            post(services::extension_host::post_extension_action),
        )
        .route(
            "/hub/workflows/publish",
            post(services::hub_workflow_publish::post_hub_workflow_publish),
        )

        // ── Service 12: Self-Improving Insights (Track 4) ──
        .route("/insights/agents/:agent_pid/optimize", get(services::insights::optimize_agent))
        .route("/insights/fleet", get(services::insights::fleet_insights))
        // E4.10-E4.12: Model rightsizing, causal analysis, self-healing
        .route("/insights/model-recommendation/:pid", get(services::insights::model_recommendation))
        .route("/insights/causal-analysis/:pid", get(services::insights::causal_analysis))
        .route("/insights/self-heal-candidates", get(services::insights::self_heal_candidates))
        .route("/insights/apply-fix/:pid/:fix_id", post(services::insights::apply_fix))
        .route("/insights/budget-forecast/:pid", get(services::insights::budget_forecast))

        // ── Service 16: Agent Registry ────────────────────────
        .route("/agents", post(services::agents::register_agent).get(services::agents::list_agents).delete(services::agents::terminate_all_agents))
        .route("/agents/:pid", get(services::agents::get_agent).patch(services::agents::update_agent).delete(services::agents::terminate_agent))
        .route("/agents/:pid/reset-budget", post(services::agents::reset_budget))
        .route("/agents/:pid/budget", axum::routing::patch(services::agents::update_budget))
        .route("/agents/:pid/cost", get(services::agents::agent_cost))
        .route("/agents/:pid/activity", get(services::agents::agent_activity))
        .route("/agents/:pid/logs", get(services::agents::agent_activity))   // alias for CLI-P2-3
        .route("/agents/:pid/signal", post(services::agents::send_agent_signal))
        .route("/agents/:pid/start", post(services::agents::start_agent))
        .route(
            "/agents/:pid/isolation",
            get(crate::substrate::cvr::api::get_agent_isolation)
                .patch(crate::substrate::cvr::api::patch_agent_isolation),
        )
        .route(
            "/agents/:pid/isolation/promote",
            post(crate::substrate::cvr::api::post_promote_isolation),
        )
        .route("/agents/:pid/kill", post(services::agents::kill_agent))
        .route(
            "/agents/:pid/operator-stop",
            post(services::agents::operator_stop),
        )
        .route(
            "/agents/:pid/kill-switch",
            post(services::aios::kill_switch),
        )
        .route("/agents/:pid/freeze", post(services::agents::freeze_agent))
        .route("/agents/:pid/thaw", post(services::agents::thaw_agent))
        .route("/agents/:pid/pause", post(services::agents::pause_agent))
        .route("/agents/:pid/cease", post(services::agents::cease_agent))
        .route(
            "/agents/:pid/expometer",
            get(services::agents::agent_expometer),
        )
        .route("/agents/:pid/resume", post(services::agents::resume_agent))
        .route("/agents/:pid/unquarantine", post(services::agents::unquarantine_agent_endpoint))
        .route("/agents/:pid/quarantine", post(services::agents::quarantine_agent_endpoint))
        // B8: SSE event stream for agent audit events (real-time tail)
        .route("/agents/:pid/events", get(services::agents::agent_event_stream))
        // B9: HITL approval gate
        .route("/agents/:pid/hitl/pending",       get(services::agents::hitl_pending))
        .route("/agents/:pid/hitl/:request_id/approve", post(services::agents::hitl_approve))
        .route("/agents/:pid/hitl/:request_id/deny",    post(services::agents::hitl_deny))
        .route("/agents/:pid/hitl", post(services::agents::hitl_create))
        .route("/agents/:pid/clearance", post(services::agents::set_clearance))
        // IIA identity / Talk / Charter (handlers existed; must be mounted for UI)
        .route("/product/tasks", post(services::augmented_task::post_product_task))
        .route("/agents/:pid/setup", get(services::agent_identity::get_agent_setup).post(services::agent_identity::post_agent_setup))
        .route("/agents/:pid/activate", post(services::agent_identity::post_agent_activate))
        .route("/agents/:pid/capabilities", get(services::agent_identity::get_agent_capabilities))
        .route("/agents/:pid/identity-envelope", get(services::agent_identity::get_agent_identity_envelope))
        .route("/agents/:pid/workspace", get(services::workspace_projection::get_agent_workspace))
        .route("/agents/:pid/preflight", get(services::workspace_projection::get_agent_preflight))
        .route(
            "/agents/:pid/presence",
            get(services::workspace_followthrough::get_presence),
        )
        .route(
            "/agents/:pid/situation",
            get(services::workspace_followthrough::get_situation)
                .post(services::workspace_followthrough::post_situation),
        )
        .route(
            "/agents/:pid/sources/:cid/eligible",
            post(services::workspace_followthrough::post_source_eligible),
        )
        .route(
            "/agents/:pid/sources/:cid/active",
            post(services::workspace_followthrough::post_source_active),
        )
        .route("/agents/:pid/activation", get(services::workspace_records::get_activation))
        .route(
            "/agents/:pid/character",
            get(services::workspace_records::get_character).put(services::workspace_records::put_character),
        )
        .route(
            "/agents/:pid/directives",
            get(services::workspace_records::list_directives).post(services::workspace_records::post_directive),
        )
        .route(
            "/agents/:pid/aliases",
            post(services::workspace_records::post_alias),
        )
        .route(
            "/agents/:pid/aliases/resolve",
            get(services::workspace_records::resolve_alias),
        )
        .route("/agents/:pid/forensic/universal", get(services::agent_identity::get_agent_forensic_universal))
        .route("/agents/:pid/compliance-contract", get(services::agent_identity::get_agent_compliance_contract))
        .route(
            "/agents/:pid/contract",
            get(services::agent_identity::get_agent_contract).patch(services::agent_identity::patch_agent_contract),
        )
        .route("/agents/:pid/completions", post(services::agent_identity::post_agent_completions))
        .route(
            "/agents/:pid/workbench/sessions",
            get(services::workbench::list_sessions).post(services::workbench::post_session),
        )
        .route(
            "/agents/:pid/workbench/sessions/:sid",
            get(services::workbench::get_session),
        )
        .route(
            "/agents/:pid/workbench/sessions/:sid/turn",
            post(services::workbench::post_turn),
        )
        .route(
            "/agents/:pid/workbench/sessions/:sid/admit",
            post(services::workbench::post_admit),
        )
        .route(
            "/agents/:pid/workbench/sessions/:sid/demo",
            post(services::workbench::post_demo),
        )
        .route(
            "/agents/:pid/workbench/sessions/:sid/cancel-orders",
            post(services::workbench::post_cancel_orders),
        )
        .route(
            "/agents/:pid/workbench/sessions/:sid/hitl-resume",
            post(services::workbench::post_hitl_resume),
        )
        .route(
            "/agents/:pid/workbench/sessions/:sid/hitl-deny",
            post(services::workbench::post_hitl_deny),
        )
        .route(
            "/agents/:pid/chat/threads",
            get(services::agent_identity::list_agent_chat_threads)
                .post(services::agent_identity::create_agent_chat_thread),
        )
        .route(
            "/agents/:pid/chat/threads/:thread_id",
            get(services::agent_identity::get_agent_chat_thread),
        )
        .route("/agents/:pid/knot/summary", get(services::agent_identity::get_agent_knot_summary))
        .route("/agents/:pid/grants", get(services::agent_identity::list_agent_grants))
        .route("/agents/:pid/cage-runtime", get(services::agents::agent_cage_runtime))
        .route(
            "/forensics/universal/:agent_pid",
            get(services::agent_identity::get_forensics_universal_by_agent),
        )
        // Route-P1-1 + CLI-P2-4: Agent-scoped memory + trace resource routes
        .route("/agents/:pid/memory",        get(services::memory2::agent_memory_list))
        .route("/agents/:pid/memory/tree",   get(services::memory2::agent_memory_tree))
        .route("/agents/:pid/memory/stats",  get(services::memory2::agent_memory_stats))
        .route("/agents/:pid/memory/search", post(services::memory2::agent_memory_search))
        .route("/agents/:pid/traces",        get(services::actionlog::agent_traces))
        .route("/actionlog/traces",          get(services::actionlog::list_traces))
        .route("/actionlog/traces/:id",      get(services::actionlog::get_trace))
        .route("/actionlog/traces/stats",    get(services::actionlog::trace_stats))
        // AIOS-A1 + AIOS-B6: agent trust override, reflection, migration
        .route("/agents/:pid/trust",         post(services::agents::set_trust_override))
        .route("/agents/:pid/reflect",       post(services::agents::trigger_reflect))
        .route("/agents/:pid/migrate",       post(services::agents::migrate_agent))
        // B14: Data residency compliance status
        .route("/agents/:pid/residency",     get(services::agents::agent_residency))
        // MEM-2 + knowledge graph
        .route("/agents/:pid/skills",        get(services::agents::agent_skills))
        .route("/agents/:pid/memory/purge",  post(services::memory2::agent_memory_purge))
        // GDPR Art.17 right-to-be-forgotten (RESTful alias for /compliance/gdpr/forget/:pid)
        .route("/agents/:pid/data",          delete(services::compliance::gdpr_forget))
        .route("/agents/:pid/memory/compact",post(services::memory2::agent_memory_compact))
        .route("/agents/:pid/memory/import", post(services::memory2::agent_memory_import))
        // AMA-2: Episode objects
        .route("/agents/:pid/episodes",      post(services::episodes::create_episode).get(services::episodes::list_episodes))
        .route("/agents/:pid/episodes/:episode_id", get(services::episodes::get_episode))
        .route("/agents/:pid/episodes/:episode_id/close", post(services::episodes::close_episode))
        // AMA-5: Policy check (access(2) analog)
        .route("/agents/:pid/policy/check",  post(services::policy_check::policy_check))
        // AMA-6: Signed audit receipts
        .route("/agents/:pid/audit/receipt/:entry_id", get(services::audit_receipts::get_audit_receipt))
        .route("/agents/:pid/audit/receipts", get(services::audit_receipts::list_audit_receipts))
        .route("/agents/:pid/audit/receipts/verify", post(services::audit_receipts::verify_receipt_chain))
        .route(
            "/agents/:pid/audit/isolation",
            get(services::compliance::agent_isolation_audit_json),
        )
        .route(
            "/agents/:pid/audit/pdf",
            get(services::compliance::agent_isolation_audit_pdf),
        )
        // CMD-1: Agent clone (fork analog)
        .route("/agents/:pid/clone",         post(services::agents::clone_agent))
        // AMA-8: Cognitive namespace path tree — /entity/{pid}/memory/{type}/
        .route("/entity/:pid/memory",        get(services::memory2::agent_memory_list))
        .route("/entity/:pid/memory/:mem_type", get(services::memory2::entity_memory_by_type))
        .route("/entity/:pid/actions",       get(services::actionlog::agent_traces))
        // AIOS-B5 + context management (canonical routes registered under Sellable Service F below)
        // XDX-2: built-in examples
        .route("/examples/:name/manifest",   get(services::deploy::example_manifest))
        .route("/run-example",               post(services::deploy::run_example))
        // BIZ-2: upgrade URL
        .route("/billing/upgrade-url",       get(services::billing::upgrade_url))

        // ── Service 17: Compliance & Evidence Export ──────────
        .route("/compliance/report", post(services::compliance::generate_report))
        .route("/compliance/report/document", get(services::compliance::compliance_report_document))
        .route("/compliance/report/pdf", get(services::compliance::compliance_report_pdf))
        .route("/compliance/scorecard", get(services::compliance::scorecard))
        .route("/compliance/findings", get(services::compliance::list_findings))
        .route("/compliance/findings/:id", get(services::compliance::get_finding).patch(services::compliance::update_finding))
        .route(
            "/compliance/findings/:id/pdf",
            get(services::compliance::finding_pdf),
        )
        .route("/compliance/frameworks", get(services::compliance::list_frameworks))
        .route("/compliance/policy-violations", get(services::compliance::policy_violations))
        .route("/compliance/data-boundary", get(services::compliance::data_boundary))
        .route("/compliance/brief/pdf", get(services::compliance::compliance_brief_pdf))
        .route("/compliance/brief/print", get(services::compliance::compliance_brief_print))
        .route("/compliance/access-report", get(services::compliance::access_report))
        .route("/compliance/gdpr/data-subjects", get(services::compliance::gdpr_data_subjects))
        .route("/compliance/gdpr/forget/:pid", post(services::compliance::gdpr_forget))
        .route("/compliance/gdpr/erasure-log", get(services::compliance::gdpr_erasure_log))
        // E1.5-E1.6: Evidence pack + drift monitor
        .route("/compliance/evidence-pack", post(services::compliance::evidence_pack))
        .route("/compliance/drift", get(services::compliance::compliance_drift))
        // E3.5-E3.7: EU AI Act, HIPAA PHI scan, ISO 42001
        .route("/compliance/eu-ai-act/risk-classification", post(services::compliance::eu_ai_act_risk_classification))
        .route("/compliance/eu-ai-act/transparency-report", get(services::compliance::eu_ai_act_transparency_report))
        .route("/compliance/eu_ai_act/risk_classification", post(services::compliance::eu_ai_act_risk_classification))
        .route("/compliance/eu_ai_act/assessment", get(services::compliance::eu_ai_act_assessment))
        .route("/compliance/eu_ai_act/log_incident", post(services::compliance::eu_ai_act_log_incident))
        .route("/compliance/hipaa/phi-scan", get(services::compliance::hipaa_phi_scan))
        .route("/compliance/hipaa/evidence-pack", get(services::compliance::hipaa_evidence_pack))
        .route("/compliance/iso42001", get(services::compliance::iso42001_report))
        // ENT-2: BAA / DPA self-serve accept (canonical)
        .route("/compliance/baa/accept", post(services::compliance::baa_accept))
        .route("/compliance/shared-responsibility", get(services::compliance::shared_responsibility))
        .route("/compliance/dpa/accept", post(services::compliance::dpa_accept))
        .route("/compliance/agreements", get(services::compliance::list_agreements))
        // NOTE: /legal/baa/accept, /legal/dpa/accept, /legal/agreements are registered
        // as deprecated redirect handlers at the bottom of this router (with Deprecated headers).
        // Do NOT add them here — that would create silent duplicates with no deprecation signal.
        // ENT-3: SOC2 controls inventory
        .route("/compliance/soc2/controls", get(services::compliance::soc2_controls))

        // ── ConnectorMap Books — Accounting-Inspired Ledger ───
        .route("/books", get(services::books::get_system_position))
        .route("/books/journal", get(services::books::get_journal))
        .route("/books/journal/:seq_no", get(services::books::get_journal_entry))
        .route("/books/ledger/:account_id", get(services::books::get_ledger))
        .route("/books/statement/:account_id", get(services::books::get_statement))
        .route("/books/receipt/:seq_no", get(services::books::get_receipt))
        .route("/books/costs", get(services::books::get_costs))
        .route("/books/balance", get(services::books::get_balance))
        .route("/books/live", get(services::books::get_live_stream))
        .route("/books/reconcile", post(services::books::run_reconciliation))
        .route("/books/close/:session_id", post(services::books::close_session))

        // ── Asset & Knowledge Pipeline (/v/ → /k/) ───────────
        // Asset containers (raw input staging in /v/ namespace)
        .route("/assets/containers", post(services::assets::create_container).get(services::assets::list_containers))
        .route("/assets/containers/:id", get(services::assets::get_container))
        .route("/assets/containers/:id/upload", post(services::assets::upload_asset))
        // Ingestion pipeline (Kafka-style: validate → clean → structure → /k/)
        .route("/assets/ingest", post(services::assets::ingest_assets))

        // ── Service 19: Notification & Reminder System ────────
        .route("/notifications", get(services::notifications::list_notifications))
        .route("/notifications/schedule", post(services::notifications::schedule_notification))
        .route("/notifications/scan", post(services::notifications::scan_and_notify))
        .route("/notifications/history", get(services::notifications::notification_history))
        .route("/certs/:key", post(services::notifications::register_cert_date))
        .route("/notifications/:id", get(services::notifications::get_notification).delete(services::notifications::cancel_notification))
        .route("/notifications/:id/acknowledge", axum::routing::patch(services::notifications::acknowledge_notification))
        // E5.5-E5.7: Deduplication, on-call schedules, templates
        .route("/notifications/schedule-dedup", post(services::notifications::schedule_with_dedup))
        .route("/notifications/dedup/:key", axum::routing::delete(services::notifications::clear_dedup))
        .route("/notifications/oncall-schedules", post(services::notifications::create_oncall_schedule).get(services::notifications::list_oncall_schedules))
        .route("/notifications/templates", get(services::notifications::list_notification_templates))
        .route("/notifications/templates/render", post(services::notifications::render_notification_template))

        // ── Service 18: Webhook Delivery ──────────────────────
        .route("/webhooks", post(services::webhooks::register_webhook).get(services::webhooks::list_webhooks))
        .route("/webhooks/events", get(services::webhooks::all_webhook_events))
        .route("/webhooks/event-types", get(services::webhooks::event_types))
        .route("/webhooks/templates", get(services::webhooks::list_templates))
        .route("/webhooks/templates/render", post(services::webhooks::render_template))
        .route("/webhooks/:id", get(services::webhooks::get_webhook).patch(services::webhooks::update_webhook).delete(services::webhooks::delete_webhook))
        .route("/webhooks/:id/test", post(services::webhooks::test_webhook))
        .route("/webhooks/:id/events", get(services::webhooks::webhook_events))
        // E5.1-E5.3: Retry queue, health score, paginated events
        .route("/webhooks/:id/retry-queue", post(services::webhooks::enqueue_retry).get(services::webhooks::list_retry_queue))
        .route("/webhooks/:id/health", get(services::webhooks::webhook_health))
        .route("/webhooks/:id/events-paged", get(services::webhooks::webhook_events_paginated))

        // ── Service 13: Licensing (Track 5) ───────────────────
        .route("/license/status", get(services::licensing::license_status))
        .route("/license/activate", post(services::licensing::license_activate))
        .route("/license/machine", get(services::licensing::machine_info))
        .route("/license/heartbeat", get(services::licensing::heartbeat))
        .route("/license/usage", get(services::licensing::usage_report))
        .route("/license/features/:feature", get(services::licensing::feature_check))
        .route("/license/tiers", get(services::licensing::list_tiers))

        // ── Service 14: Auth + RBAC + 2FA ─────────────────────
        // NOTE: /auth/signup is registered below under billing (BIZ-1) — billing::signup is the real impl
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/change-password", post(auth::change_password))
        .route("/auth/totp/setup", post(auth::totp_setup))
        .route("/auth/totp/verify", post(auth::totp_verify))
        .route("/auth/api-keys", post(auth::create_api_key))
        .route("/auth/keys", get(auth::list_keys).post(auth::create_api_key))
        .route("/auth/users", get(auth::list_users))
        .route("/auth/users/role", post(auth::admin_set_role))
        .route("/auth/rbac/permissions", get(rbac_permissions))
        .route("/auth/rbac/roles", get(rbac_roles))
        // ENT-4: SSO OIDC (Okta, Google, Azure AD, GitHub, any OIDC provider)
        .route("/auth/sso/login", get(auth::sso_login))
        .route("/auth/sso/callback", get(auth::sso_callback))

        // ── Service 15: Binary Distribution Portal ────────────
        .route("/distribution/download-link", post(distribution_download_link))
        .route("/distribution/releases", get(distribution_releases))
        .route("/distribution/verify", post(distribution_verify_binary))

        // ── Service 16: Notebook / Interactive Playground ─────
        .route("/playground", get(services::notebook::playground))
        .route("/playground/execute", post(services::notebook::execute))
        .route("/playground/kernel", get(services::notebook::kernel_info))
        .route("/playground/snippets", get(services::notebook::snippets))
        // Hosted SaaS trial sessions (tenant-isolated sandboxes)
        .route("/playground/status", get(services::playground::playground_status))
        .route("/playground/session", post(services::playground::start_session))
        .route(
            "/playground/session/export",
            get(services::playground_export::export),
        )
        .route(
            "/playground/session/:id",
            get(services::playground::get_session).delete(services::playground::end_session),
        )
        .route("/playground/sessions", get(services::playground::list_sessions))
        .route(
            "/import/playground-session",
            post(services::playground_export::import),
        )
        .route(
            "/telemetry/playground",
            post(services::telemetry_playground::record),
        )
        .route("/notebook/execute", post(services::notebook::execute))
        .route("/notebook/kernel", get(services::notebook::kernel_info))
        .route("/notebook/snippets", get(services::notebook::snippets))

        // ── Sellable Service A: Formal Verification ──
        // Canonical routes live under /safety/formal/* — deprecated aliases below at build_router() merge site

        // ── Sellable Service C: Grounding + Claims Verification ──
        .route("/grounding/tables", post(services::grounding::upload_table).get(services::grounding::list_tables))
        .route("/grounding/lookup", post(services::grounding::lookup))
        .route("/grounding/ground-output", post(services::grounding::ground_output))
        .route("/grounding/stats", get(services::grounding::stats))
        .route("/grounding/claims/verify", post(services::grounding::verify_claim))
        .route("/grounding/claims/verify-batch", post(services::grounding::verify_batch))
        .route("/grounding/claims/ground-and-verify", post(services::grounding::ground_and_verify))

        // ── Sellable Service D: Agent Economy (Escrow + Pricing + Reputation + Negotiation) ──
        .route("/economy/deposit", post(services::economy::deposit))
        .route("/economy/balance/:pid", get(services::economy::balance))
        .route("/economy/escrow/lock", post(services::economy::escrow_lock))
        .route("/economy/escrow/:id/release", post(services::economy::escrow_release))
        .route("/economy/escrow/:id/slash", post(services::economy::escrow_slash))
        .route("/economy/escrow/:id/dispute", post(services::economy::escrow_dispute))
        .route("/economy/escrow/:id", get(services::economy::escrow_status))
        .route("/economy/settlements", get(services::economy::settlements))
        .route("/economy/quote", post(services::economy::price_quote))
        .route("/economy/budget-gate", post(services::economy::set_budget_gate))
        .route("/economy/budget-gate/:pid", get(services::economy::budget_gate_status))
        // NOTE: /economy/reputation/* deprecated aliases merged below at build_router() merge site
        .route("/economy/negotiate/propose", post(services::economy::negotiate_propose))
        .route("/economy/negotiate/:id/counter", post(services::economy::negotiate_counter))
        .route("/economy/negotiate/:id/accept", post(services::economy::negotiate_accept))
        .route("/economy/negotiate/:id/reject", post(services::economy::negotiate_reject))
        .route("/economy/negotiate/:id", get(services::economy::negotiate_status))
        .route("/economy/negotiate", get(services::economy::negotiate_list))

        // ── Sellable Service E: Agent Marketplace ──
        .route("/marketplace/contracts", post(services::marketplace::publish_contract).get(services::marketplace::list_contracts))
        .route("/marketplace/contracts/:pid", get(services::marketplace::get_contract))
        .route("/marketplace/discover", post(services::marketplace::discover))
        .route("/marketplace/index", get(services::marketplace::browse_index))
        .route("/marketplace/index/:pid", get(services::marketplace::agent_capabilities))
        .route("/marketplace/index/:pid/health", post(services::marketplace::update_health))
        .route("/marketplace/rankings", get(services::marketplace::rankings))
        // AMA-9: Tool marketplace + module registry
        .route("/marketplace/tools",            get(services::marketplace::list_tools))
        .route("/marketplace/tools/register",   post(services::marketplace::register_tool))
        .route("/marketplace/agents",           get(services::marketplace::list_marketplace_agents))
        .route("/marketplace/modules",          get(services::marketplace::list_modules))
        .route("/marketplace/modules/install",  post(services::marketplace::install_module))
        .route("/marketplace/modules/:module_id", axum::routing::delete(services::marketplace::uninstall_module))

        // ── Sellable Service F: Context Lifecycle ──
        .route("/context/:pid/snapshot", post(services::context::snapshot))
        .route("/context/:pid/restore/:cid", post(services::context::restore))
        .route("/context/:pid/compress", post(services::context::compress))
        .route("/context/:pid/evict", post(services::context::evict))
        .route("/context/:pid/resume", post(services::context::resume))
        .route("/context/:pid/snapshots", get(services::context::list_snapshots))
        .route("/context/:pid/pressure", get(services::context::pressure))

        // ── Sellable Service G: Adaptive Firewall ──
        .route("/firewall/thresholds/:pid", get(services::firewall_config::agent_thresholds))
        .route("/firewall/baselines", get(services::firewall_config::baselines))
        .route("/firewall/adjustments", get(services::firewall_config::adjustments))
        .route("/firewall/inspect", post(services::firewall_config::inspect_content))
        .route("/firewall/false-positives/:pid", get(services::firewall_config::false_positives))

        // NOTE: /orchestrator/* deprecated aliases merged below (DAG vs saga — separate Link successors)

        // ── Service 17: Payment (async-stripe, PCI-compliant) ──
        .route("/payment/plans", get(services::payment::list_plans))
        .route("/payment/checkout", post(services::payment::checkout))
        .route("/payment/portal", post(services::payment::portal))
        .route("/payment/webhook", post(services::payment::webhook))
        .route("/payment/status", get(services::payment::payment_status))

        // ── Service 18: Memory2 — P0 Gap Fills ───────────────
        // Sessions
        .route("/memory/sessions", post(services::memory2::create_session))
        .route("/memory/sessions/list", get(services::memory2::list_sessions))
        .route("/memory/sessions/:session_id/close", post(services::memory2::close_session))
        .route("/memory/sessions/:session_id/packets", get(services::memory2::session_packets))
        // Packet by CID
        .route("/memory/packets/:cid", get(services::memory2::get_packet))
        .route("/memory/packets/:cid/seal", post(services::memory2::seal_packet))
        // Access revoke
        .route("/memory/access/revoke", post(services::memory2::revoke_access))
        // Global cross-agent keyword search
        .route("/memory/search", get(services::memory2::global_memory_search))
        // Full recall (all 9 fields + filters)
        .route("/memory/recall2/:namespace", get(services::memory2::recall_full))
        // Fixed RAG (time_range + grounding wired)
        .route("/memory/knowledge/query2", post(services::memory2::knowledge_query_full))
        // Real interference engine (StateVector + compute_interference)
        .route("/memory/interference2/:agent_pid", get(services::memory2::interference_real))
        // Knowledge Graph
        .route("/memory/graph/entities", get(services::memory2::graph_entities))
        .route("/memory/graph/neighbors/:entity_id", get(services::memory2::graph_neighbors))
        .route("/memory/graph/entity", post(services::memory2::add_graph_entity))
        .route("/memory/graph/edge", post(services::memory2::add_graph_edge))
        .route("/memory/graph/seed", post(services::memory2::load_knowledge_seed))
        .route("/memory/knowledge/compile", post(services::memory2::knowledge_compile))
        .route("/memory/graph/growth-events/:agent_pid", get(services::memory2::graph_growth_events))

        // ── Service 19: AAPI — Full Action Authorization Plane ──
        // UCAN capabilities
        .route("/aapi/capabilities/issue", post(services::aapi::issue_capability))
        .route("/aapi/capabilities/delegate", post(services::aapi::delegate_capability))
        .route("/aapi/capabilities", get(services::aapi::list_capabilities))
        .route("/aapi/capabilities/:token_id", axum::routing::delete(services::aapi::revoke_capability))
        .route("/aapi/capabilities/:token_id/verify", get(services::aapi::verify_capability))
        // Budgets
        .route("/aapi/budgets", post(services::aapi::create_budget))
        .route("/aapi/budgets/consume", post(services::aapi::consume_budget))
        .route("/aapi/budgets/reserve", post(services::aapi::bcr_reserve))
        .route("/aapi/budgets/commit", post(services::aapi::bcr_commit))
        .route("/aapi/budgets/release", post(services::aapi::bcr_release))
        .route("/aapi/budgets/:agent_pid/:resource", get(services::aapi::get_budget))
        .route("/aapi/inverse/register", post(services::aapi::register_inverse))
        .route("/aapi/compensate", post(services::aapi::compensate))
        .route("/aapi/ledger/:agent_pid", get(services::aapi::get_durable_ledger))
        // Dynamic policies
        .route("/aapi/policies", post(services::aapi::add_policy))
        .route("/aapi/policies/:id", axum::routing::delete(services::aapi::remove_policy))
        .route("/aapi/policies/evaluate", post(services::aapi::evaluate_policy))
        // Regulatory templates
        .route("/aapi/policies/hipaa", post(services::aapi::apply_hipaa_policy))
        .route("/aapi/policies/financial", post(services::aapi::apply_financial_policy))
        // Tool authorization
        .route("/aapi/tools/authorize", post(services::aapi::authorize_tool))
        .route("/aapi/tools/register", post(services::aapi::register_tool_aapi))
        // Interaction log
        .route("/aapi/interactions", get(services::aapi::list_interactions).post(services::aapi::log_interaction))
        // Compliance
        .route("/aapi/compliance", post(services::aapi::set_compliance))

        // ── Service 20: Cognitive Pipeline ───────────────────
        .route("/cognitive/observe", post(services::cognitive::observe))
        .route("/cognitive/context/:agent_pid", get(services::cognitive::perceived_context))
        .route("/cognitive/plan", post(services::cognitive::create_plan))
        .route("/cognitive/reasoning/step", post(services::cognitive::record_reasoning_step))
        .route("/cognitive/reasoning/conclude", post(services::cognitive::record_conclusion))
        .route("/cognitive/judgment", post(services::cognitive::run_judgment))
        .route("/cognitive/cycle", post(services::cognitive::cognitive_cycle))
        .route("/cognitive/report/:agent_pid", get(services::cognitive::cognitive_report))

        // ── Service 21: Protocol Bridges ─────────────────────
        // MCP Client
        .route("/protocols/mcp/discover", post(services::protocols::mcp_discover))
        .route("/protocols/mcp/call", post(services::protocols::mcp_call_tool))
        .route("/protocols/mcp/servers", get(services::protocols::mcp_list_servers))
        // MCP Server (platform as MCP server)
        .route("/protocols/mcp/handle", post(services::protocols::mcp_handle))
        .route("/protocols/mcp/tools", get(services::protocols::mcp_list_tools))
        // A2A
        .route("/protocols/a2a/card", get(services::protocols::a2a_agent_card))
        .route("/protocols/a2a/card/read", post(services::protocols::read_remote_agent_card))
        .route("/protocols/a2a/tasks", post(services::protocols::a2a_send_task))
        .route("/protocols/a2a/tasks/:task_id", get(services::protocols::a2a_get_task))
        .route("/protocols/a2a/tasks/:task_id/subscribe", get(services::protocols::a2a_subscribe_task))
        .route("/protocols/a2a/tasks/:task_id/cancel", post(services::protocols::a2a_cancel_task))
        // ACP
        .route("/protocols/acp/messages", post(services::protocols::acp_send))
        .route("/protocols/acp/messages/:message_id", get(services::protocols::acp_status))
        // ANP
        .route("/protocols/anp/dids", post(services::protocols::anp_register_did).get(services::protocols::anp_list_dids))
        .route("/protocols/anp/dids/:did", get(services::protocols::anp_resolve_did))
        // AP2
        .route("/protocols/ap2/mandates", post(services::protocols::ap2_create_mandate).get(services::protocols::ap2_list_mandates))
        .route("/protocols/ap2/mandates/:mandate_id", get(services::protocols::ap2_get_mandate))

        // ── Service 22: Hallucination Safety + Formal Verification ──
        .route("/safety/grounding/lookup", post(services::safety::grounding_lookup))
        .route("/safety/grounding/categories", get(services::safety::grounding_categories))
        .route("/safety/grounding/add", post(services::safety::grounding_add))
        .route("/safety/grounding/verify", post(services::safety::grounding_verify))
        .route("/safety/claims/verify", post(services::safety::claims_verify))
        .route("/safety/claims/status", get(services::safety::claims_status))
        .route("/safety/formal/verify", get(services::safety::formal_verify_all))
        .route("/safety/formal/invariants", get(services::safety::formal_list_invariants))
        // Fleet / auditor verification (same handlers as legacy GET /verify/* — canonical paths)
        .route("/safety/formal/report", get(services::verify::report))
        .route("/safety/formal/violations", get(services::verify::violations))
        .route("/safety/formal/snapshot", get(services::verify::get_snapshot))

        // ── Service 23: Distributed Infra + Agent Consensus ──
        // BFT Consensus
        .route("/infra/consensus/propose", post(services::infra::bft_propose))
        .route("/infra/consensus/vote", post(services::infra::bft_vote))
        .route("/infra/consensus/status", get(services::infra::bft_status))
        .route("/infra/consensus/validators", post(services::infra::bft_set_validators))
        // Cross-cell routing
        .route("/infra/cells/route", post(services::infra::cross_cell_route))
        .route("/infra/cells/status", get(services::infra::cross_cell_status))
        // Global quota
        .route("/infra/quota/set", post(services::infra::quota_set))
        .route("/infra/quota/:namespace", get(services::infra::quota_check))
        .route("/infra/quota", get(services::infra::quota_list))
        // Adaptive router
        .route("/infra/router/metrics", post(services::infra::router_update_metrics))
        .route("/infra/router/route", post(services::infra::router_route))
        .route("/infra/router/cells", get(services::infra::router_cells))
        // Context lifecycle
        .route("/infra/context/register", post(services::infra::context_register))
        .route("/infra/context/snapshot", post(services::infra::context_snapshot))
        .route("/infra/context/restore", post(services::infra::context_restore))
        .route("/infra/context/evict", post(services::infra::context_evict))
        // Secret vault
        .route("/infra/vault/secrets", post(services::infra::vault_store))
        .route("/infra/vault/resolve", post(services::infra::vault_resolve))
        .route("/infra/vault/redact", post(services::infra::vault_redact))
        .route("/infra/vault/status", get(services::infra::vault_status))
        // DAG orchestrator (infra layer)
        .route("/infra/orchestrator/submit", post(services::infra::orchestrator_submit))
        // Saga inventory + rollback (canonical; must be before :orch_id so "sagas" is not captured as an id)
        .route("/infra/orchestrator/sagas/:id/rollback", post(services::orchestrator::saga_rollback))
        .route("/infra/orchestrator/sagas/:id", get(services::orchestrator::saga_status))
        .route("/infra/orchestrator/sagas", get(services::orchestrator::list_sagas))
        .route("/infra/orchestrator/:orch_id", get(services::infra::orchestrator_status))
        .route("/infra/orchestrator", get(services::infra::orchestrator_list))
        // EigenTrust reputation
        .route("/infra/reputation/stake", post(services::infra::reputation_stake))
        .route("/infra/reputation/feedback", post(services::infra::reputation_feedback))
        .route("/infra/reputation/scores", get(services::infra::reputation_scores))
        .route("/infra/reputation/slash", post(services::infra::reputation_slash))

        // ── TC-2: Token Container lifecycle ──────────────────────────────────
        .route("/infra/tc/issue",          post(services::infra::tc_issue))
        .route("/infra/tc/rotate",         post(services::infra::tc_rotate))
        .route("/infra/tc/reduce",         post(services::infra::tc_reduce))
        .route("/infra/tc/revoke",         post(services::infra::tc_revoke))
        // TC-5: Crypto module registry
        .route("/infra/tc/crypto-modules", get(services::infra::tc_crypto_modules))

        // ── Phase 12: System Verification ─────────────────────────────────────
        .route("/system/verify",      get(services::infra::system_verify))
        .route("/system/verify/full", post(services::infra::system_verify_full))
        .route("/agents/:pid/verify", get(services::infra::agent_verify))

        // ── BIZ-4/5: Billing Service ────────────────────────────
        .route("/billing/usage", get(services::billing::billing_usage))
        .route("/billing/entitlements", get(services::billing::billing_entitlements))
        .route("/billing/record-usage", post(services::billing::record_usage))
        .route("/billing/invoices", get(services::billing::billing_invoices))
        .route("/billing/portal", get(services::billing::billing_portal))
        // BIZ-1: instant signup, no credit card required
        .route("/auth/signup", post(services::billing::signup))
        // D6/SMOKE-10: Stripe webhook
        .route("/billing/stripe/webhook", post(services::billing::stripe_webhook))
        // BIZ-7: Analytics / activation funnel telemetry
        // FIX BUG-042: Chain GET and POST on same path (axum 0.7 panics on duplicate .route() calls)
        .route("/analytics/events", get(services::analytics::list_events).post(services::analytics::emit_event))
        .route("/analytics/funnel", get(services::analytics::funnel))

        // ── AIOS-A6: Deploy + Registry ─────────────────────────
        .route("/deploy", post(services::deploy::deploy))
        .route("/deploy/validate", post(services::deploy::validate_deploy))
        .route("/deploy/rollback", post(services::deploy::rollback))
        .route("/deploy/list", get(services::deploy::list_deployed))
        .route("/deploy/history/:name", get(services::deploy::history))
        .route("/deploy/diff/:name", get(services::deploy::diff))
        // ── AIOS-B12: Blue-green upgrade + promote ──────────────
        .route("/deploy/upgrade", post(services::deploy::upgrade))
        .route("/deploy/upgrade/promote", post(services::deploy::upgrade_promote))

        // ── Docs / Migration ─────────────────────────────────────────────────
        .route("/docs/migration", get(migration_guide))

        // ── Legal → Compliance redirects (deprecated aliases) ────────────────
        .route("/legal/baa/accept", post(legal_redirect_baa))
        .route("/legal/dpa/accept", post(legal_redirect_dpa))
        .route("/legal/agreements", get(legal_redirect_agreements))

        // ── CLS Contract API ─────────────────────────────────────────────────
        .route("/cls/compile", post(services::cls::compile))
        .route("/cls/playground", post(services::cls::playground))
        .route("/cls/packages", get(services::cls::list_packages).post(services::cls::register_package))
        .route("/cls/packages/:id", get(services::cls::get_package_detail))
        .route("/cls/packages/:id/install", post(services::cls::install_package))
        .route("/cls/packages/:id/bind", post(services::cls::bind_package))
        .route("/cls/packages/:id/lifecycle", post(services::cls::lifecycle_action))
        .route("/cls/packages/:id/execution", get(services::cls::get_execution_surface))
        .route("/cls/packages/:id/execution/export", get(services::cls::export_execution_report))
        .route("/cls/packages/:id/execution/runs/:run_id", get(services::cls::get_execution_run_detail))
        .route("/contracts/templates", get(services::cls::list_templates))
        .route("/contracts/templates/:id", get(services::cls::get_template_detail))
        .route("/agents/:agent_id/contract/from-template", post(services::cls::from_template))
        .route("/agents/:agent_id/contract/simple", post(services::cls::simple_contract))

        // ── Phase R1: Internal DNS debug endpoint ─────────────────────────────
        .route("/internal/dns", get(internal_dns_handler))

        .with_state(state.clone());   // ← single state binding for entire api router
        // FIX BUG-046: Removed duplicate rate_limit_middleware here — applied once after merge at line ~909

    // ── Fix-2: Deprecated route sub-Routers — ACTUALLY sends headers on the wire ──
    // Each family is extracted into its own Router, wrapped with with_deprecation_headers(),
    // then nested into the api router so every response includes:
    //   Deprecated: true  |  Sunset: 1.0.0  |  Link: <canonical>; rel="successor-version"

    // /verify/* → /safety/formal/* (split so Link headers name the matching successor)
    let deprecated_verify_report = with_deprecation_headers(
        Router::new()
            .route("/verify/report", get(services::verify::report))
            .with_state(state.clone()),
        r#"</api/v1/safety/formal/report>; rel="successor-version""#,
        "1.0.0",
    );
    let deprecated_verify_violations = with_deprecation_headers(
        Router::new()
            .route("/verify/violations", get(services::verify::violations))
            .with_state(state.clone()),
        r#"</api/v1/safety/formal/violations>; rel="successor-version""#,
        "1.0.0",
    );
    let deprecated_verify_snapshot = with_deprecation_headers(
        Router::new()
            .route("/verify/snapshot", get(services::verify::get_snapshot))
            .with_state(state.clone()),
        r#"</api/v1/safety/formal/snapshot>; rel="successor-version""#,
        "1.0.0",
    );
    let deprecated_verify_invariants = with_deprecation_headers(
        Router::new()
            .route("/verify/invariants", get(services::verify::check_all))
            .route("/verify/invariants/:name", get(services::verify::check_one))
            .with_state(state.clone()),
        r#"</api/v1/safety/formal/verify>; rel="successor-version""#,
        "1.0.0",
    );

    // /secrets/* → /infra/vault/*
    let deprecated_secrets = with_deprecation_headers(
        Router::new()
            .route("/secrets/store",          post(services::secrets::store_secret))
            .route("/secrets/handle",         post(services::secrets::issue_handle))
            .route("/secrets/resolve",        post(services::secrets::resolve_handle))
            .route("/secrets/handles/:pid",   get(services::secrets::list_handles))
            .route("/secrets/:id",            axum::routing::delete(services::secrets::revoke_secret))
            .route("/secrets/:id/rotate",     post(services::secrets::rotate_secret))
            .route("/secrets/audit",          get(services::secrets::audit_trail))
            .with_state(state.clone()),
        "/api/v1/infra/vault/secrets",
        "1.0.0",
    );

    // /orchestrator/* → /infra/orchestrator/* (split so Link matches DAG vs saga successors)
    let deprecated_orchestrator_dag = with_deprecation_headers(
        Router::new()
            .route("/orchestrator/dag",                  post(services::orchestrator::create_dag))
            .route("/orchestrator/dag/:id",              get(services::orchestrator::dag_status))
            .route("/orchestrator/dag/:id/advance",      post(services::orchestrator::dag_advance))
            .route("/orchestrator/dag/:id/plan",         get(services::orchestrator::dag_plan))
            .route("/orchestrator/dag/:id/retry",        post(services::orchestrator::dag_retry))
            .with_state(state.clone()),
        r#"</api/v1/infra/orchestrator/submit>; rel="successor-version""#,
        "1.0.0",
    );
    let deprecated_orchestrator_sagas = with_deprecation_headers(
        Router::new()
            .route("/orchestrator/sagas",                get(services::orchestrator::list_sagas))
            .route("/orchestrator/sagas/:id",            get(services::orchestrator::saga_status))
            .route("/orchestrator/sagas/:id/rollback",   post(services::orchestrator::saga_rollback))
            .with_state(state.clone()),
        r#"</api/v1/infra/orchestrator/sagas>; rel="successor-version""#,
        "1.0.0",
    );

    // /economy/reputation/* → /infra/reputation/*
    let deprecated_reputation = with_deprecation_headers(
        Router::new()
            .route("/economy/reputation/stake",        post(services::economy::register_stake))
            .route("/economy/reputation/feedback",     post(services::economy::submit_feedback))
            .route("/economy/reputation/slash/:pid",   post(services::economy::reputation_slash))
            .route("/economy/reputation/scores",       get(services::economy::reputation_scores))
            .route("/economy/reputation/scores/:pid",  get(services::economy::reputation_score))
            .with_state(state.clone()),
        "/api/v1/infra/reputation/scores",
        "1.0.0",
    );

    // Merge all deprecated sub-routers into the api router (nested at /api/v1 below)
    let api = api
        .merge(deprecated_verify_report)
        .merge(deprecated_verify_violations)
        .merge(deprecated_verify_snapshot)
        .merge(deprecated_verify_invariants)
        .merge(deprecated_secrets)
        .merge(deprecated_orchestrator_dag)
        .merge(deprecated_orchestrator_sagas)
        .merge(deprecated_reputation)
        .layer(axum::middleware::from_fn(trace_context_middleware))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::substrate::spine_shell::middleware,
        ))
        // Fix-5: Auth middleware layer — every /api/v1/* request checked unless allowlisted
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        // B20: Per-API-key + per-agent + global rate limiting (sliding window, 429 + Retry-After)
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        // B21: Request body size limits (default 10MB, configurable via CONNECTOR_MAX_BODY_SIZE_MB)
        .layer(crate::middleware::body_limit_layer())
        // XDX-6: dev-mode request log (no-op in prod)
        .layer(axum::middleware::from_fn(dev_log_middleware))
        // XDX-5: Connector-Version header on every API response
        .layer(axum::middleware::from_fn(connector_version_header_middleware));

    // ── AI Gateway routes (OpenAI-compatible, D2 fix) ────────────────────────
    // Any SDK with a `base_url` override gets full audit coverage with zero code changes.
    // e.g. OpenAI Python: client = OpenAI(base_url="http://this-server", api_key="cp-...")
    // FIX BUG-047: Added auth and rate limiting middleware (was missing, allowing unauthenticated LLM calls)
    let gateway = Router::new()
        .route("/v1/chat/completions", post(services::gateway::chat_completions))
        .route("/v1/models", get(services::gateway::list_models))
        // ── DevGuard: Anthropic Messages API (Claude Code integration) ──
        .route("/v1/messages", post(services::anthropic_gateway::anthropic_messages))
        .route("/v1/messages/count_tokens", post(services::anthropic_gateway::anthropic_count_tokens))
        .layer(axum::middleware::from_fn(trace_context_middleware))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::substrate::spine_shell::middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        .with_state(state.clone());

    // ── DevGuard: Coding Agent Control Plane routes ──────────────────────
    let devguard = Router::new()
        // Canonical repository binding and admission.
        .route("/api/v1/devguard/connect", post(services::devguard::connect))
        .route("/api/v1/devguard/connect/info", get(services::devguard::connect_info))
        .route("/api/v1/devguard/admit", post(services::devguard::admit))
        .route(
            "/api/v1/devguard/tokens/:token_key/revoke",
            post(services::devguard::revoke_token),
        )
        // Canonical plural session contract used by the dashboard and CLI.
        .route(
            "/api/v1/devguard/sessions",
            get(services::devguard::session_list).post(services::devguard::session_start),
        )
        .route(
            "/api/v1/devguard/sessions/:id",
            get(services::devguard::session_status),
        )
        .route(
            "/api/v1/devguard/sessions/:id/end",
            post(services::devguard::session_end),
        )
        .route(
            "/api/v1/devguard/sessions/:id/audit",
            get(services::devguard::audit_trail),
        )
        // Compatibility aliases for pre-v1 clients.
        .route("/api/v1/devguard/session/start", post(services::devguard::session_start))
        .route("/api/v1/devguard/session/:id", get(services::devguard::session_status))
        .route("/api/v1/devguard/session/:id", delete(services::devguard::session_end))
        .route("/api/v1/devguard/audit/:session_id", get(services::devguard::audit_trail))
        // Tenant-scoped repository registry and governed node workspace.
        .route("/api/v1/devguard/repos", get(services::devguard::list_repos))
        .route("/api/v1/devguard/repos/:repo_id", get(services::devguard::get_repo))
        .route(
            "/api/v1/devguard/repos/:repo_id/agents",
            post(services::devguard::attach_agent),
        )
        .route(
            "/api/v1/devguard/repos/:repo_id/roles",
            post(services::devguard::put_owner_roles),
        )
        .route(
            "/api/v1/devguard/repos/:repo_id/tree",
            get(services::devguard_workspace::list_tree),
        )
        .route(
            "/api/v1/devguard/repos/:repo_id/file",
            get(services::devguard_workspace::get_file)
                .put(services::devguard_workspace::put_file)
                .delete(services::devguard_workspace::delete_file),
        )
        .route(
            "/api/v1/devguard/repos/:repo_id/git/:op",
            post(services::devguard_workspace::git_op),
        )
        // Policy management
        .route("/api/v1/devguard/policy/load", post(services::policy_config::policy_load))
        .route("/api/v1/devguard/policy/validate", post(services::policy_config::policy_validate))
        .route("/api/v1/devguard/policy/check", post(services::policy_config::policy_check))
        .route("/api/v1/devguard/policy/history", post(services::policy_config::policy_history))
        .route("/api/v1/devguard/policy/rollback", post(services::policy_config::policy_rollback))
        // Guards
        .route("/api/v1/devguard/fs/check", post(services::fs_guard::fs_check))
        .route("/api/v1/devguard/fs/guard", post(services::fs_guard::fs_guard_content))
        .route("/api/v1/devguard/exec/check", post(services::exec_guard::exec_check))
        // Secret scanning
        .route("/api/v1/devguard/secrets/scan", post(services::secret_broker::secrets_scan))
        // Audit
        // Plugin setup/status and workstation extension proxy.
        .route("/api/v1/plugins/status", get(services::plugins_status::get_plugins_status))
        .route(
            "/api/v1/plugins/service-map",
            get(services::plugins_status::get_plugins_service_map),
        )
        .route(
            "/api/v1/plugins/:id/configure/schema",
            get(services::plugin_configure::get_plugin_settings_schema),
        )
        .route(
            "/api/v1/plugins/:id/configure",
            get(services::plugin_configure::get_plugin_settings_values)
                .post(services::plugin_configure::set_plugin_settings_values),
        )
        .route(
            "/api/v1/plugins/devguard/local-profile",
            get(services::devguard_local_profile::get_local_profile)
                .post(services::devguard_local_profile::post_local_profile),
        )
        .route(
            "/api/v1/devguard/workspaces/discover",
            get(services::devguard_local_profile::discover_workspaces),
        )
        .route(
            "/api/v1/devguard/github/status",
            get(services::devguard_github::github_status),
        )
        .route(
            "/api/v1/devguard/github/checks/evaluate",
            post(services::devguard_github::evaluate_check),
        )
        .route(
            "/api/v1/devguard/github/checks/:repo_id/:head_sha",
            get(services::devguard_github::get_check),
        )
        .route(
            "/api/v1/plugins/devguard/status",
            get(services::devguard_proxy::dg_proxy_status),
        )
        .route(
            "/api/v1/plugins/devguard/extension/status",
            get(services::devguard_proxy::dg_extension_status),
        )
        .route(
            "/api/v1/plugins/devguard/extension/audit/:session_id",
            get(services::devguard_proxy::dg_extension_audit),
        )
        // Team control plane.
        .route(
            "/api/v1/plugins/devguard/teams",
            get(services::devguard_team::list_teams)
                .post(services::devguard_team::create_team),
        )
        .route(
            "/api/v1/plugins/devguard/teams/:team_id",
            get(services::devguard_team::get_team),
        )
        .route(
            "/api/v1/plugins/devguard/teams/:team_id/members",
            get(services::devguard_team::list_members)
                .post(services::devguard_team::add_member),
        )
        .route(
            "/api/v1/plugins/devguard/teams/:team_id/members/:member_id/role",
            put(services::devguard_team::update_member_role)
                .post(services::devguard_team::update_member_role),
        )
        .route(
            "/api/v1/plugins/devguard/teams/:team_id/actions",
            get(services::devguard_team::list_actions)
                .post(services::devguard_team::log_action),
        )
        .route(
            "/api/v1/plugins/devguard/teams/:team_id/command-center",
            get(services::devguard_team::command_center),
        )
        .route(
            "/api/v1/plugins/devguard/roles",
            get(services::devguard_team::get_roles),
        )
        .layer(axum::middleware::from_fn(trace_context_middleware))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::substrate::spine_shell::middleware,
        ))
        .with_state(state.clone());

    // ── Infrastructure routes (no /api/v1 prefix) ────────
    // Probes stay public. Metrics / OpenAPI / docs require auth under productionish
    // unless CONNECTOR_METRICS_PUBLIC=1 or CONNECTOR_DOCS_PUBLIC=1.
    let infra_public = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/boot/progress", get(boot_progress_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(ready))
        .route("/version", get(version_handler))
        .route("/api/version", get(api_version_handler))
        .route("/api/v1/auth/token", post(auth::auth_token_legacy))
        .route("/api/v1", get(api_manifest))
        .route("/api/v1/", get(api_manifest))
        .route("/.well-known/agent.json", get(a2a_agent_card))
        .with_state(state.clone());

    let metrics_public = std::env::var("CONNECTOR_METRICS_PUBLIC")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || !crate::connector_profile::is_productionish_env();
    let docs_public = std::env::var("CONNECTOR_DOCS_PUBLIC")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || !crate::connector_profile::is_productionish_env();

    let mut infra_protected = Router::new()
        .route("/dev/requests", get(dev_requests_handler))
        .route("/dev/requests/clear", delete(dev_requests_clear_handler));
    if metrics_public {
        infra_protected = infra_protected.route("/metrics", get(metrics_handler));
    }
    if docs_public {
        infra_protected = infra_protected
            .route("/openapi.json", get(openapi_spec))
            .route("/openapi.yaml", get(openapi_spec_yaml))
            .route("/docs", get(swagger_ui))
            .route("/docs/", get(swagger_ui));
    }
    let infra_protected = infra_protected.with_state(state.clone());

    let mut infra_auth = Router::new();
    if !metrics_public {
        infra_auth = infra_auth.route("/metrics", get(metrics_handler));
    }
    if !docs_public {
        infra_auth = infra_auth
            .route("/openapi.json", get(openapi_spec))
            .route("/openapi.yaml", get(openapi_spec_yaml))
            .route("/docs", get(swagger_ui))
            .route("/docs/", get(swagger_ui));
    }
    let infra_auth = infra_auth
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let infra = infra_public.merge(infra_protected).merge(infra_auth);

    let api_v2 = crate::api_v2::v2_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::substrate::spine_shell::v2_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    // ── Static file serving for UIs ──────────────────────────
    // Dashboard UI: ui/dist → served at /
    // SPA fallback: non-API paths → index.html for client-side routing
    // NOTE: Portal (www) is now served by control server (connector-license-server)

    // DevGuard routes were previously merged without auth; nest under same RBAC layer.
    // UI: filesystem dist wins; else compile-time embed (real Trunk dist or honest stub).
    let outer = Router::new()
        .nest("/api/v1", api)
        .nest("/api/v2", api_v2)
        .merge(infra)
        .merge(gateway)
        .merge(
            devguard.layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware)),
        )
        // Cage reverse proxy (was orphaned) — nest strips `/plugin` for handler path parse.
        .nest(
            "/plugin",
            Router::new().fallback(axum::routing::any(
                services::plugin_cage_proxy::plugin_cage_forward,
            )),
        )
        .layer(tower_http::cors::CorsLayer::permissive())
        .fallback(axum::routing::any(serve_ui_fallback));

    outer.with_state(state)
}

/// Disk UI if present; otherwise embedded dashboard (never silent 404 for `/`).
async fn serve_ui_fallback(req: axum::http::Request<Body>) -> axum::response::Response {
    use std::sync::Arc;
    let ui_dir = resolve_dashboard_ui_dir();
    if dashboard_ui_index_file(Path::new(&ui_dir)).is_some() {
        return serve_with_compression(req).await;
    }
    let spa = Arc::new(bytes::Bytes::copy_from_slice(
        crate::dashboard_embed::index_html_raw(),
    ));
    match crate::dashboard_embed::serve_embedded_or_spa(req, spa).await {
        Ok(resp) => resp,
        Err(_) => axum::response::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("dashboard embed failed"))
            .unwrap(),
    }
}

/// GET /api/v1/boot/progress — polled by connectorctl start to show live boot stages.
///
/// No auth required: available as soon as the HTTP listener is up (after ACCESS stage).
/// Returns stage-by-stage completion for the 12-stage boot sequence.
async fn boot_progress_handler() -> impl IntoResponse {
    use std::sync::atomic::Ordering;
    use crate::boot::{BOOT_STAGES_COMPLETE, BOOT_STAGE_COUNT, BOOT_STAGE_NAMES, NODE_READY, BOOT_START_MS};

    let bits = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst);
    let stages_complete = bits.count_ones() as u16;
    let is_ready = NODE_READY.load(Ordering::SeqCst);

    // Find the highest completed stage name
    let last_complete = (0..BOOT_STAGE_COUNT)
        .filter(|i| (bits & (1 << i)) != 0)
        .last();
    let current_stage = last_complete.unwrap_or(0) as u16;
    let current_stage_name = BOOT_STAGE_NAMES
        .get(current_stage as usize)
        .copied()
        .unwrap_or("STARTING");

    let boot_time_ms = BOOT_START_MS.load(Ordering::SeqCst);
    let elapsed_ms = if boot_time_ms > 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            .saturating_sub(boot_time_ms)
    } else {
        0
    };

    let stage_list: Vec<serde_json::Value> = (0..BOOT_STAGE_COUNT as u16)
        .map(|i| {
            let done = (bits & (1 << i)) != 0;
            serde_json::json!({
                "index": i,
                "name": BOOT_STAGE_NAMES.get(i as usize).unwrap_or(&""),
                "complete": done,
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "stages_complete": stages_complete,
        "stages_total": BOOT_STAGE_COUNT,
        "progress_pct": (stages_complete * 100) / BOOT_STAGE_COUNT,
        "current_stage": current_stage,
        "current_stage_name": current_stage_name,
        "current_stage_message": "",
        "boot_time_ms": elapsed_ms,
        "ready": is_ready,
        "stages": stage_list,
    }))
}

/// GET /ready + GET /readyz — readiness probe for load balancers and k8s.
///
/// AMA-7: Returns 503 until all 7 boot stages complete (PLATFORM_READY atomic flag = 1).
/// Boot stages (bit positions):
///   0=VAC store, 1=kernel+policies, 2=context mgr, 3=LLM scheduler,
///   4=UCAN verifier, 5=agent restore, 6=HTTP router
///
/// Kernel checks use a bounded try_lock so a stuck Talk/RAG cannot hang readiness forever.
async fn ready(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> impl IntoResponse {
    use std::sync::atomic::Ordering;
    use crate::{PLATFORM_READY, BOOT_STAGE};

    // AMA-7: primary gate — all 7 boot stages must complete
    let boot_ready = PLATFORM_READY.load(Ordering::SeqCst) == 1;
    let boot_stages = BOOT_STAGE.load(Ordering::SeqCst);

    // Bounded kernel touch — never block like Talk RAG does on the same mutex.
    let (kernel_ok, audit_chain_ok, kernel_busy) =
        match crate::concurrency::kernel_handle::try_lock_kernel_for(
            state.as_ref(),
            crate::concurrency::kernel_handle::READY_TRY_LOCK_TIMEOUT,
        ) {
            Some(k) => {
                let audit = k.verify_audit_chain().is_ok();
                (true, audit, false)
            }
            None => (false, false, true),
        };
    let license_ok = state.license.agent_limit() > 0;
    let llm_ready = state.llm_router.read().map(|g| g.is_some()).unwrap_or(false);

    // All stages must pass for 200 (busy kernel ⇒ not ready, but probe returns quickly)
    let ready = boot_ready && kernel_ok && audit_chain_ok && license_ok;

    let body = serde_json::json!({
        "ready": ready,
        "boot_stages_complete": boot_stages,
        "boot_stages_required": 0b0111_1111u8,
        "checks": {
            "boot_gate":   boot_ready,
            "kernel":      kernel_ok,
            "kernel_busy": kernel_busy,
            "audit_chain": audit_chain_ok,
            "license":     license_ok,
            "llm":         llm_ready,
        },
        "note": if !boot_ready {
            format!("Platform still booting — stages complete: {}/7 (bitmask: {:07b})", boot_stages.count_ones(), boot_stages)
        } else if kernel_busy {
            "Kernel lock busy (Talk/RAG in progress) — retry readiness shortly.".to_string()
        } else if !llm_ready {
            "All 7 boot stages complete. LLM not wired (set CONNECTOR_LLM_API_KEY) — AI Gateway unavailable.".to_string()
        } else {
            "All systems operational.".to_string()
        }
    });

    if ready {
        (StatusCode::OK, axum::Json(body))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body))
    }
}

/// GET /health — liveness only. Never waits on the VAC/kernel mutex.
async fn health(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> impl IntoResponse {
    let runtime_mode = *state.runtime_mode.read().unwrap();
    let agents = state.health.agents();
    let agent_cap = {
        let snap = state.health.agent_cap();
        if snap == 0 {
            crate::services::agents::resolved_kernel_agent_cap(state.as_ref())
        } else {
            snap
        }
    };
    let tier = format!("{:?}", state.license.tier);
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "connector-platform",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": runtime_mode.as_str(),
        "license": tier,
        "agents": format!("{}/{}", agents, agent_cap),
        "agents_honesty": if crate::services::playground::is_playground_mode() {
            "Kernel pool on this shared node — not visitor agent count. Each session is one Demo agent (MAX_AGENTS=1)."
        } else {
            "Kernel agent pool vs license/runtime cap."
        },
        "visitor_agents_per_session": if crate::services::playground::is_playground_mode() {
            serde_json::json!(crate::services::playground::max_agents())
        } else {
            serde_json::Value::Null
        },
        "capabilities": ["memory", "cognitive_cycle", "hallucination_safety", "protocols", "distributed_infra", "audit_log", "multiagent", "firewall"],
        "protocols": ["CNP", "MCP", "A2A", "ACP", "ANP", "AP2"],
        "safety": ["grounding", "claims_verification", "formal_invariants_x6"],
        "manifest": "GET /api/v1",
        "quickstart": "GET /api/v1",
    }))
}

async fn api_manifest(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    let runtime_mode = *state.runtime_mode.read().unwrap();
    let agents = state.health.agents();
    let agent_cap = {
        let snap = state.health.agent_cap();
        if snap == 0 {
            crate::services::agents::resolved_kernel_agent_cap(state.as_ref())
        } else {
            snap
        }
    };
    let packet_limit = state.license.packet_limit();
    let tier = format!("{:?}", state.license.tier);

    let airgap = std::env::var("CONNECTOR_AIRGAP")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let expose_defense = std::env::var("CONNECTOR_EXPOSE_DEFENSE_DETAIL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    axum::Json(serde_json::json!({
        "connector_platform": env!("CARGO_PKG_VERSION"),
        "mode": runtime_mode.as_str(),
        "auth": if matches!(runtime_mode, RuntimeMode::Dev) {
            serde_json::json!({"type": "dev", "header": "Authorization: Bearer dev-token", "note": "Any token works in CONNECTOR_DEV_MODE=1"})
        } else if matches!(runtime_mode, RuntimeMode::Pilots) {
            serde_json::json!({"type": "pilot", "obtain": "connectorctl admin pilot create", "note": "Scoped pilot API keys with expiry and per-scope access"})
        } else {
            serde_json::json!({"type": "jwt", "obtain": "POST /api/v1/auth/token"})
        },
        "license": {
            "tier": tier,
            "agents": format!("{}/{}", agents, agent_cap),
            "packets": if packet_limit == usize::MAX { "unlimited".to_string() } else { packet_limit.to_string() },
        },
        "defense_posture": if expose_defense {
            serde_json::json!({
                "airgap": airgap,
                "defense_strict": crate::services::runtime_control::defense_strict_enabled(),
                "dev_auth_bypass": crate::services::runtime_control::dev_auth_bypass_allowed(),
                "note": "Sovereign / distributed AIOS: set CONNECTOR_AIRGAP=1, CONNECTOR_DEFENSE_STRICT=1, strong CONNECTOR_JWT_SECRET, Production runtime mode. Omit CONNECTOR_EXPOSE_DEFENSE_DETAIL in untrusted environments."
            })
        } else {
            serde_json::json!({
                "hint": "Set CONNECTOR_EXPOSE_DEFENSE_DETAIL=1 for airgap / bypass flags (operators only)."
            })
        },
        "quickstart": [
            {"step": 1, "action": "Register agent", "method": "POST", "path": "/api/v1/agents", "body": {"name": "my-agent", "namespace": "m/my-agent", "note": "Use m/... private memory namespaces (BF2-U02)"}},
            {"step": 2, "action": "Write memory",   "method": "POST", "path": "/api/v1/memory/write",    "body": {"content": "User likes dark mode", "agent_pid": "<kernel_pid from step 1 response>"}},
            {"step": 3, "action": "Recall memory",  "method": "GET",  "path": "/api/v1/memory/recall/m/my-agent"},
        ],
        "api_v2": {
            "base": "/api/v2",
            "note": "Structured REST surface (agents, memory, tools, sessions, audit, health) — parallel to legacy /api/v1 paths where applicable"
        },
        "surfaces": {
            "description": "Validated SOE output for dashboards, integrations, and clients",
            "route": "GET /api/v1/surfaces/:surface/:subject_id",
            "query": {
                "view": "summary|ops|forensic|exec",
                "time": "now|@<ts>|since:<ts>|before:<ts>|range:<start>..<end>|last:15m|event:<id>|snapshot:<id>",
                "page": 1,
                "page_size": 50,
                "search": "policy",
                "filter": ["severity=critical"],
                "sort": ["-timestamp"]
            }
        },
        "capabilities": {
            "memory":          {"status": "enabled", "routes": 8,  "description": "Persistent CID-addressed memory with bi-temporal queries"},
            "cognitive_cycle": {"status": "enabled", "routes": 4,  "description": "ReAct-equivalent: observe, plan, act, reflect"},
            "hallucination_safety": {"status": "enabled", "routes": 8,  "description": "Grounding tables + claims verification + 6 TLA+ formal invariants"},
            "protocols":       {"status": "enabled", "routes": 18, "description": "CNP native stack surface + MCP client/server, A2A, ACP, ANP, AP2 bridges"},
            "distributed_infra":{"status": "enabled", "routes": 27, "description": "BFT consensus, EigenTrust reputation, DAG orchestrator, secret vault"},
            "audit_log":       {"status": "enabled", "routes": 9,  "description": "Full action log, OTEL export, compliance report"},
            "multiagent":      {"status": "enabled", "routes": 7,  "description": "Multi-agent mesh, namespace grants, shared knowledge plane, UCAN capabilities"},
            "firewall":        {"status": "enabled", "routes": 5,  "description": "LLM output firewall with adaptive thresholds"},
            "payment":         {"status": if std::env::var("STRIPE_SECRET_KEY").is_ok() { "enabled" } else { "requires STRIPE_SECRET_KEY" }, "routes": 8, "description": "Agent-to-agent payments via Stripe"},
        },
        "gateway": {
            "description": "OpenAI-compatible LLM proxy — use a SEPARATE base URL (not /api/v1)",
            "base_url": "/v1",
            "endpoints": [
                {"method": "POST", "path": "/v1/chat/completions", "note": "Drop-in replacement for OpenAI SDK"},
                {"method": "GET",  "path": "/v1/models"}
            ],
            "sdk_example": "from openai import OpenAI; client = OpenAI(base_url='http://localhost:8080/v1', api_key='cpk_...')",
            "note": "The gateway lives at /v1/* (root), NOT under /api/v1/. All gateway calls are audited, injection-checked, and budget-gated."
        },
        "deprecated_routes_note": "All deprecated routes below ACTUALLY return `Deprecated: true`, `Sunset: 1.0.0`, and `Link: <canonical>; rel=successor-version` response headers — enforced at the router layer, not just in docs.",
        "deprecated_routes": [
            {
                "path": "/api/v1/memory/recall2/:namespace",
                "deprecated_since": "0.3.0",
                "reason": "Suffix version removed from public API. /memory/recall/:namespace now serves the full memory2 handler with all filters.",
                "use_instead": "/api/v1/memory/recall/:namespace",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "path": "/api/v1/memory/knowledge/query2",
                "deprecated_since": "0.3.0",
                "reason": "Suffix version removed. /memory/knowledge/query now serves the full RAG handler with time_range and grounding.",
                "use_instead": "/api/v1/memory/knowledge/query",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "path": "/api/v1/memory/interference2/:agent_pid",
                "deprecated_since": "0.3.0",
                "reason": "Suffix version removed. /memory/interference/:agent_pid now serves the real StateVector computation.",
                "use_instead": "/api/v1/memory/interference/:agent_pid",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "path": "/api/v1/secrets/*",
                "deprecated_since": "0.2.0",
                "reason": "Moved to infra layer for consistency",
                "use_instead": "/api/v1/infra/vault/*",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "path": "/api/v1/orchestrator/*",
                "deprecated_since": "0.2.0",
                "reason": "Duplicate of infra orchestrator",
                "use_instead": "/api/v1/infra/orchestrator/*",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "path": "/api/v1/verify/*",
                "deprecated_since": "0.2.0",
                "reason": "Merged into safety service",
                "use_instead": "/api/v1/safety/formal/*",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "path": "/api/v1/economy/reputation/*",
                "deprecated_since": "0.2.0",
                "reason": "Canonical reputation lives in infra layer",
                "use_instead": "/api/v1/infra/reputation/*",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "path": "/api/v1/legal/*",
                "deprecated_since": "0.2.0",
                "reason": "Consolidated into compliance service",
                "use_instead": "/api/v1/compliance/*",
                "will_remove": "1.0.0"
            }
        ],
        "docs": "https://connector.dev/docs",
        "openapi": "/openapi.json",
        "health": "/health",
        "migration": "/api/v1/docs/migration",
        "tip": "Start with POST /api/v1/agents — everything else follows from there."
    }))
}

async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> impl IntoResponse {
    {
        let k = state.kernel.lock().unwrap();
        let ctx = state.context_mgr.lock().unwrap();

        let mut active_count: i64 = 0;
        let mut suspended_count: i64 = 0;
        let mut active_by_ns: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

        for (pid, acb) in k.agents() {
            let status = format!("{:?}", acb.status).to_lowercase();
            if status.contains("running") || status.contains("healthy") {
                active_count += 1;
                *active_by_ns.entry(acb.namespace.clone()).or_insert(0) += 1;
            }
            if status.contains("suspended") || status.contains("paused") {
                suspended_count += 1;
            }

            let budget = crate::services::multiagent::agent_token_budget() as f64;
            let budget_pct = if budget > 0.0 {
                (acb.total_tokens_consumed as f64 / budget * 100.0).min(100.0)
            } else {
                0.0
            };

            let ctx_pct = ctx.get(pid)
                .map(|c| (c.pressure() * 100.0).min(100.0))
                .unwrap_or(budget_pct);

            state.metrics.context_utilization_by_agent
                .get_or_create(&AgentLabels { agent_pid: pid.clone() })
                .set(ctx_pct);
        }

        state.metrics.agents_active.set(active_count);
        state.metrics.agents_suspended.set(suspended_count);

        for (namespace, count) in active_by_ns {
            state.metrics.agents_active_by_ns
                .get_or_create(&NamespaceLabels { namespace })
                .set(count);
        }
    }

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.encode(),
    )
}

// ── RBAC info endpoints ──────────────────────────────────────

async fn rbac_permissions(
    axum::extract::State(state): axum::extract::State<SharedState>,
    headers: axum::http::HeaderMap,
) -> axum::Json<serde_json::Value> {
    let claims = headers.get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .and_then(|t| auth::verify_token(t).ok());

    match claims {
        Some(c) => axum::Json(serde_json::json!({
            "user_id": c.sub,
            "role": c.role,
            "permissions": c.permissions,
            "all_roles": [
                {"role": "super_admin", "rank": 6, "permissions": auth::PlatformRole::SuperAdmin.permissions().len()},
                {"role": "admin", "rank": 5, "permissions": auth::PlatformRole::Admin.permissions().len()},
                {"role": "operator", "rank": 4, "permissions": auth::PlatformRole::Operator.permissions().len()},
                {"role": "developer", "rank": 3, "permissions": auth::PlatformRole::Developer.permissions().len()},
                {"role": "viewer", "rank": 2, "permissions": auth::PlatformRole::Viewer.permissions().len()},
                {"role": "service", "rank": 1, "permissions": auth::PlatformRole::Service.permissions().len()},
            ],
        })),
        None => axum::Json(serde_json::json!({"error": "Unauthorized"})),
    }
}

async fn rbac_roles() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "roles": [
            {"role": "super_admin", "rank": 6, "description": "Full access + user management + license admin", "permissions": auth::PlatformRole::SuperAdmin.permissions()},
            {"role": "admin", "rank": 5, "description": "Full access to all services", "permissions": auth::PlatformRole::Admin.permissions()},
            {"role": "operator", "rank": 4, "description": "Read/write to services, no user management", "permissions": auth::PlatformRole::Operator.permissions()},
            {"role": "developer", "rank": 3, "description": "Read/write to most services, no admin", "permissions": auth::PlatformRole::Developer.permissions()},
            {"role": "viewer", "rank": 2, "description": "Read-only access", "permissions": auth::PlatformRole::Viewer.permissions()},
            {"role": "service", "rank": 1, "description": "Machine-to-machine API key with scoped permissions", "permissions": auth::PlatformRole::Service.permissions()},
        ]
    }))
}

// ── Binary distribution endpoints ────────────────────────────

async fn distribution_download_link(
    axum::extract::State(state): axum::extract::State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    // Requires authenticated user with valid license
    let claims = headers.get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .and_then(|t| auth::verify_token(t).ok());

    let claims = match claims {
        Some(c) => c,
        None => return axum::Json(serde_json::json!({"error": "Authentication required"})),
    };

    let platform = req.get("platform").and_then(|v| v.as_str()).unwrap_or("linux");
    let arch = req.get("arch").and_then(|v| v.as_str()).unwrap_or("amd64");
    let version = req.get("version").and_then(|v| v.as_str()).unwrap_or("latest");

    let lic = &state.license;
    let download_token = format!("dl_{}_{}", claims.sub, uuid::Uuid::new_v4());

    // Binary is fingerprinted with instance_id
    let binary_id = format!("bin_{}_{}_{}_{}_{}",
        format!("{:?}", lic.tier).to_lowercase(),
        &lic.instance_id[..8.min(lic.instance_id.len())],
        platform, arch, version
    );

    axum::Json(serde_json::json!({
        "download_url": format!("https://releases.connector.dev/v/{}/connector-platform-{}-{}?token={}", version, platform, arch, download_token),
        "binary_id": binary_id,
        "instance_id": &lic.instance_id,
        "tier": format!("{:?}", lic.tier),
        "platform": platform,
        "arch": arch,
        "version": version,
        "download_token": download_token,
        "expires_in_secs": 3600,
        "checksum_url": format!("https://releases.connector.dev/v/{}/connector-platform-{}-{}.sha256", version, platform, arch),
        "signature_url": format!("https://releases.connector.dev/v/{}/connector-platform-{}-{}.sig", version, platform, arch),
        "note": "Binary is tied to your license instance_id. Validated on startup.",
    }))
}

async fn distribution_releases() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "current": "0.1.0",
        "releases": [
            {"version": "0.1.0", "date": "2026-03-01", "channel": "stable", "platforms": ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"]},
        ],
        "channels": ["stable", "beta", "nightly"],
    }))
}

async fn distribution_verify_binary(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let binary_hash = req.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
    let instance_id = req.get("instance_id").and_then(|v| v.as_str()).unwrap_or("");
    let machine_id = req.get("machine_id").and_then(|v| v.as_str()).unwrap_or("");

    let lic = &state.license;
    let instance_match = instance_id == lic.instance_id;

    axum::Json(serde_json::json!({
        "verified": !binary_hash.is_empty() && instance_match,
        "instance_match": instance_match,
        "binary_hash_provided": !binary_hash.is_empty(),
        "machine_id": machine_id,
        "tier": format!("{:?}", lic.tier),
        "note": "Binary integrity and license binding verified",
    }))
}

// ── B17: Kubernetes-standard probe endpoints ──────────────────────────────────

/// GET /healthz — minimal liveness probe (no DB access, always 200 if process is up)
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(serde_json::json!({ "ok": true })))
}

/// GET /version — machine-readable build metadata
async fn version_handler() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name":    env!("CARGO_PKG_NAME"),
        "commit":  option_env!("GIT_COMMIT").unwrap_or("unknown"),
        "built_at": option_env!("BUILD_TIME").unwrap_or("unknown"),
        "rust":    option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
    }))
}

// =============================================================================
// XDX-5: GET /api/version — machine-readable API version + deprecation warnings
// =============================================================================

/// GET /api/version — returns version, api_version, deprecation_warnings.
///
/// Pattern mirrors Stripe's `Stripe-Version` header + version pinning model.
/// Clients can use `deprecation_warnings` to detect fields/endpoints being retired.
async fn api_version_handler() -> impl IntoResponse {
    let dev_mode = std::env::var("CONNECTOR_DEV_MODE").is_ok()
        || std::env::var("CONNECTOR_ENV").map(|v| v == "development" || v == "dev").unwrap_or(false);

    // Known active deprecations — add entries here when retiring endpoints/fields
    let deprecation_warnings: Vec<serde_json::Value> = vec![
        // Example (uncomment when retiring a field):
        // serde_json::json!({
        //     "type": "field",
        //     "location": "KernelAuditEntry.note",
        //     "message": "Renamed to `reason` in v2. Remove by: 2027-03-01.",
        //     "sunset": "2027-03-01",
        //     "migration": "https://connector.ai/docs/migration/v2#audit-entry"
        // }),
    ];

    axum::Json(serde_json::json!({
        "version":     env!("CARGO_PKG_VERSION"),
        "api_version": "v1",
        "min_supported_client": "0.1.0",
        "commit":      option_env!("GIT_COMMIT").unwrap_or("unknown"),
        "built_at":    option_env!("BUILD_TIME").unwrap_or("unknown"),
        "profile":     if cfg!(debug_assertions) { "debug" } else { "release" },
        "dev_mode":    dev_mode,
        "deprecation_warnings": deprecation_warnings,
        "changelog":   "https://connector.ai/changelog",
        "migration":   "https://connector.ai/docs/migration",
        "note": "Pin your integration with: Connector-Version: <version>. Breaking changes announced 90 days in advance.",
    }))
}

// =============================================================================
// XDX-6: GET /dev/requests — last 100 requests (dev mode only, like rails server log)
// =============================================================================

/// GET /dev/requests — returns the last 100 requests as JSON array.
///
/// Only returns data in CONNECTOR_ENV=development / CONNECTOR_DEV_MODE=1.
/// Returns 403 in production to prevent information leakage.
/// Mirrors Rails server request log but accessible from a browser or `curl`.
async fn dev_requests_handler() -> impl IntoResponse {
    let dev_mode = std::env::var("CONNECTOR_DEV_MODE").is_ok()
        || std::env::var("CONNECTOR_ENV").map(|v| v == "development" || v == "dev").unwrap_or(false);

    if !dev_mode {
        return (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({
            "ok": false,
            "error": {
                "code": "dev_only",
                "message": "GET /dev/requests is only available in CONNECTOR_ENV=development mode.",
                "hint": "Set CONNECTOR_DEV_MODE=1 or CONNECTOR_ENV=development to enable."
            }
        }))).into_response();
    }

    let log = match DEV_REQUEST_LOG.lock() {
        Ok(l) => l.iter().cloned().collect::<Vec<_>>(),
        Err(_) => vec![],
    };

    (StatusCode::OK, axum::Json(serde_json::json!({
        "ok": true,
        "count": log.len(),
        "max": DEV_REQUEST_LOG_SIZE,
        "requests": log,
        "note": "Last 100 requests. Clear with: DELETE /dev/requests/clear",
    }))).into_response()
}

/// DELETE /dev/requests/clear — flush the dev request log ring-buffer.
async fn dev_requests_clear_handler() -> impl IntoResponse {
    let dev_mode = std::env::var("CONNECTOR_DEV_MODE").is_ok()
        || std::env::var("CONNECTOR_ENV").map(|v| v == "development" || v == "dev").unwrap_or(false);

    if !dev_mode {
        return (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({
            "ok": false,
            "error": { "code": "dev_only", "message": "Only available in development mode." }
        }))).into_response();
    }

    if let Ok(mut log) = DEV_REQUEST_LOG.lock() {
        log.clear();
    }

    (StatusCode::OK, axum::Json(serde_json::json!({
        "ok": true,
        "message": "Dev request log cleared."
    }))).into_response()
}

/// GET /openapi.yaml — OpenAPI 3.1 spec in YAML format
async fn openapi_spec_yaml() -> impl IntoResponse {
    // Convert the JSON spec to YAML representation for tools that prefer it
    let spec = openapi_spec_value();
    match serde_yaml::to_string(&spec) {
        Ok(yaml) => (
            StatusCode::OK,
            [("content-type", "application/yaml")],
            yaml,
        ).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "YAML serialization failed".to_string()).into_response(),
    }
}

// ── SMOKE-14: A2A AgentCard discovery ────────────────────────────────────────

/// GET /.well-known/agent.json — A2A Protocol v1.0 AgentCard discovery endpoint.
/// Returns the platform's AgentCard so external agents can discover capabilities.
async fn a2a_agent_card(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> impl IntoResponse {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = std::env::var("CONNECTOR_PUBLIC_URL")
        .unwrap_or_else(|_| "http://localhost:9091".to_string());

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::json!({
            "schema_version": "1.0",
            "name": "Connector Platform",
            "description": "Self-hosted AI agent governance runtime with memory, security, billing, and compliance",
            "version": version,
            "url": base_url,
            "skills": [
                {
                    "id": "llm_proxy",
                    "name": "LLM Gateway",
                    "description": "OpenAI-compatible LLM proxy with injection detection and audit",
                    "input_modes": ["text"],
                    "output_modes": ["text"],
                    "endpoints": { "chat": format!("{}/v1/chat/completions", base_url) }
                },
                {
                    "id": "agent_memory",
                    "name": "Agent Memory",
                    "description": "CID-addressed persistent memory with bi-temporal queries",
                    "input_modes": ["data"],
                    "output_modes": ["data"],
                    "endpoints": { "write": format!("{}/api/v1/memory/write", base_url), "recall": format!("{}/api/v1/memory/recall", base_url) }
                },
                {
                    "id": "hitl",
                    "name": "Human-in-the-Loop",
                    "description": "Human approval gate for pipeline steps",
                    "input_modes": ["data"],
                    "output_modes": ["data"],
                    "endpoints": { "approve": format!("{}/api/v1/multiagent/pipelines/{{pipeline_id}}/approve-step/{{step}}", base_url) }
                }
            ],
            "supported_input_modes": ["text", "data", "file"],
            "supported_output_modes": ["text", "data"],
            "authentication": {
                "schemes": ["bearer"],
                "description": "JWT or cpk_live_* API key in Authorization header"
            },
            "capabilities": {
                "streaming": false,
                "push_notifications": false,
                "state_transition_history": true
            },
            "provider": {
                "organization": "Connector AI",
                "url": "https://connector.ai",
                "docs": "https://connector.ai/docs"
            },
            "license_tier": format!("{:?}", state.license.tier).to_lowercase(),
        }).to_string(),
    )
}

// ── XDX-1: OpenAPI spec + Swagger UI ─────────────────────────────────────────

/// Shared OpenAPI 3.1 spec value (reused by JSON + YAML handlers).
fn openapi_spec_value() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.1.0",
            "info": {
                "title": "Connector Platform API",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Self-hosted AI governance and agent runtime platform",
                "contact": { "url": "https://connector.ai/docs" },
                "license": { "name": "Commercial", "url": "https://connector.ai/license" }
            },
            "servers": [
                { "url": "/api/v1", "description": "Production API" },
                { "url": "http://localhost:8080/api/v1", "description": "Local development" }
            ],
            "security": [{ "BearerAuth": [] }],
            "components": {
                "securitySchemes": {
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT or cpk_live_* API key",
                        "description": "Use `cpk_live_*` API key or JWT from POST /auth/login"
                    }
                },
                "schemas": {
                    "ApiErrorEnvelope": {
                        "type": "object",
                        "required": ["schema", "code", "message"],
                        "properties": {
                            "schema": { "type": "string", "const": "connector.api.error.v1" },
                            "code": { "type": "string", "example": "package_gate" },
                            "message": { "type": "string" },
                            "phase": { "type": "string" },
                            "retry_safe": { "type": "boolean" },
                            "operation_id": { "type": "string" },
                            "trace_id": { "type": "string" },
                            "detail": { "type": "object" }
                        }
                    },
                    "PackagePin": {
                        "type": "object",
                        "required": ["schema", "package_id", "package_digest"],
                        "properties": {
                            "schema": { "type": "string", "const": "connector.package_gate.v1" },
                            "package_id": { "type": "string" },
                            "package_digest": { "type": "string" },
                            "ir_digest": { "type": "string" },
                            "signature_present": { "type": "boolean" },
                            "kind": { "type": "string" }
                        }
                    }
                }
            },
            "tags": [
                { "name": "Auth", "description": "Authentication, signup, SSO, 2FA, API keys" },
                { "name": "Agents", "description": "Agent lifecycle: register, start, suspend, terminate" },
                { "name": "Memory", "description": "Persistent CID-addressed memory with bi-temporal queries" },
                { "name": "Gateway", "description": "OpenAI-compatible LLM proxy with governance" },
                { "name": "Billing", "description": "Usage-based metered billing, entitlements, Stripe portal" },
                { "name": "Compliance", "description": "BAA/DPA acceptance, SOC2 controls, audit reports" },
                { "name": "Multiagent", "description": "Multi-agent sessions, HITL approve/deny, namespace grants" },
                { "name": "Monitoring", "description": "Health, readiness, Prometheus metrics" },
                { "name": "Pipeline", "description": "Guard pipeline, KECS sweep, cognitive cycle" },
                { "name": "Infra", "description": "Consensus, WAL, reputation, vault, orchestrator" },
                { "name": "Surfaces", "description": "SOE — validated output surfaces with contract enforcement, role-based redaction, and structured queries" },
                { "name": "Native", "description": "CNKTROS native surfaces, channels, invocations, packages, proxy" }
            ],
            "paths": {
                "/native/invocations": {
                    "post": {
                        "tags": ["Native"],
                        "summary": "Native invoke through ActionBinding/PATE (requires PackagePin outside lab)",
                        "operationId": "native_invoke",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "package": { "$ref": "#/components/schemas/PackagePin" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": { "description": "Invocation + EdgeReceipt" },
                            "default": {
                                "description": "Structured denial",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "ok": { "type": "boolean", "const": false },
                                                "error": { "$ref": "#/components/schemas/ApiErrorEnvelope" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/native/proxy/routes": {
                    "post": {
                        "tags": ["Native"],
                        "summary": "Publish embedded route graph (requires PackagePin outside lab)",
                        "operationId": "native_put_route_graph",
                        "responses": {
                            "200": { "description": "Route graph stored" },
                            "default": {
                                "description": "Structured denial",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "ok": { "type": "boolean" },
                                                "error": { "$ref": "#/components/schemas/ApiErrorEnvelope" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                // ── Auth ──────────────────────────────────────────────────────
                "/auth/signup": {
                    "post": { "tags": ["Auth"], "summary": "Instant signup — API key returned immediately, no credit card", "operationId": "signup",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["email","password"], "properties": {
                            "email": { "type": "string", "format": "email", "example": "dev@acme.com" },
                            "password": { "type": "string", "minLength": 8, "example": "hunter2secret" },
                            "org": { "type": "string", "example": "Acme Inc" }
                        } } } } },
                        "responses": { "200": { "description": "API key issued" } }, "security": [] }
                },
                "/auth/token": {
                    "post": { "tags": ["Auth"], "summary": "Login → JWT + API key", "operationId": "auth_token",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["email","password"], "properties": {
                            "email": { "type": "string", "example": "dev@acme.com" },
                            "password": { "type": "string", "example": "hunter2secret" }
                        } } } } },
                        "responses": { "200": { "description": "JWT access token + refresh token" } }, "security": [] }
                },
                "/auth/api-keys": {
                    "post": { "tags": ["Auth"], "summary": "Create API key with optional scopes and expiry", "operationId": "create_api_key",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": {
                            "name": { "type": "string", "example": "ci-pipeline" },
                            "scopes": { "type": "array", "items": { "type": "string" }, "example": ["agents:read","memory:write"] },
                            "expires_in_days": { "type": "integer", "example": 90 }
                        } } } } },
                        "responses": { "200": { "description": "cpk_live_* API key" } } }
                },
                "/auth/me": {
                    "get": { "tags": ["Auth"], "summary": "Current user identity, role, permissions", "operationId": "me",
                        "responses": { "200": { "description": "User profile + permissions" } } }
                },
                // ── Agents ────────────────────────────────────────────────────
                "/agents": {
                    "get":  { "tags": ["Agents"], "summary": "List all registered agents", "operationId": "list_agents",
                        "parameters": [
                            { "name": "status", "in": "query", "schema": { "type": "string", "enum": ["Running","Suspended","Terminated"] } },
                            { "name": "namespace", "in": "query", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "Agent list" } } },
                    "post": { "tags": ["Agents"], "summary": "Register a new agent", "operationId": "register_agent",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["name","namespace"], "properties": {
                            "name": { "type": "string", "example": "my-agent" },
                            "namespace": { "type": "string", "example": "production" },
                            "description": { "type": "string" },
                            "clearance": { "type": "string", "enum": ["public","confidential","secret","top_secret"], "example": "confidential" },
                            "token_budget": { "type": "object", "properties": { "daily_limit": { "type": "integer", "example": 100000 } } }
                        } } } } },
                        "responses": { "200": { "description": "Agent created with pid" } } }
                },
                "/agents/{pid}": {
                    "get": { "tags": ["Agents"], "summary": "Inspect a single agent", "operationId": "get_agent",
                        "parameters": [{ "name": "pid", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "responses": { "200": { "description": "AgentControlBlock JSON" }, "404": { "description": "Not found" } } },
                    "delete": { "tags": ["Agents"], "summary": "Terminate and delete an agent", "operationId": "delete_agent",
                        "parameters": [{ "name": "pid", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "responses": { "200": { "description": "Agent terminated" } } }
                },
                "/agents/{pid}/pause": {
                    "post": { "tags": ["Agents"], "summary": "Pause (suspend) agent", "operationId": "pause_agent",
                        "parameters": [{ "name": "pid", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "responses": { "200": { "description": "Agent suspended" } } }
                },
                "/agents/{pid}/resume": {
                    "post": { "tags": ["Agents"], "summary": "Resume a suspended agent", "operationId": "resume_agent",
                        "parameters": [{ "name": "pid", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "responses": { "200": { "description": "Agent running" } } }
                },
                "/agents/{pid}/clearance": {
                    "post": { "tags": ["Agents"], "summary": "Update agent security clearance level", "operationId": "set_clearance",
                        "parameters": [{ "name": "pid", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["level"], "properties": {
                            "level": { "type": "string", "enum": ["public","confidential","secret","top_secret"], "example": "secret" }
                        } } } } },
                        "responses": { "200": { "description": "Clearance updated" } } }
                },
                // ── Memory ────────────────────────────────────────────────────
                "/memory/write": {
                    "post": { "tags": ["Memory"], "summary": "Write a memory packet (CID-addressed, bi-temporal)", "operationId": "write_memory",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["content","agent_pid"], "properties": {
                            "content": { "type": "string", "example": "User prefers dark mode" },
                            "agent_pid": { "type": "string", "example": "my-agent" },
                            "namespace": { "type": "string", "example": "production" },
                            "session_id": { "type": "string" },
                            "packet_type": { "type": "string", "enum": ["Observation","Reflection","Feedback","Instruction","Skill","Goal"], "example": "Observation" },
                            "tags": { "type": "array", "items": { "type": "string" }, "example": ["onboarding","ux"] },
                            "pin": { "type": "boolean", "default": false }
                        } } } } },
                        "responses": { "200": { "description": "Packet written, CID returned" } } }
                },
                "/memory/recall/{namespace}": {
                    "get": { "tags": ["Memory"], "summary": "Recall memory packets with full filters (canonical path — serves memory2 handler)", "operationId": "recall_memory",
                        "parameters": [
                            { "name": "namespace", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 50 } },
                            { "name": "packet_type", "in": "query", "schema": { "type": "string" } },
                            { "name": "session_id", "in": "query", "schema": { "type": "string" } },
                            { "name": "since_ms", "in": "query", "schema": { "type": "integer" } },
                            { "name": "until_ms", "in": "query", "schema": { "type": "integer" } }
                        ],
                        "responses": { "200": { "description": "Packet list with full fields including cid, session_id, packet_type, timestamp_ms, sealed, pinned" } } }
                },
                "/memory/semantic-search": {
                    "get": { "tags": ["Memory"], "summary": "Semantic search across memory packets", "operationId": "semantic_search",
                        "parameters": [
                            { "name": "q", "in": "query", "required": true, "schema": { "type": "string", "example": "user preferences" } },
                            { "name": "namespace", "in": "query", "schema": { "type": "string" } },
                            { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 10 } }
                        ],
                        "responses": { "200": { "description": "Ranked packet results with similarity scores" } } }
                },
                "/memory/knowledge/query": {
                    "post": { "tags": ["Memory"], "summary": "RAG knowledge query with time_range + grounding (canonical)", "operationId": "knowledge_query",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["query"], "properties": {
                            "query": { "type": "string", "example": "What are the user's UI preferences?" },
                            "namespace": { "type": "string" },
                            "top_k": { "type": "integer", "default": 5 },
                            "time_range": { "type": "object", "properties": { "since_ms": { "type": "integer" }, "until_ms": { "type": "integer" } } }
                        } } } } },
                        "responses": { "200": { "description": "Retrieved chunks with similarity scores" } } }
                },
                // ── Cognitive ─────────────────────────────────────────────────
                "/cognitive/cycle": {
                    "post": { "tags": ["Pipeline"], "summary": "Run full ReAct cognitive cycle: observe→plan→act→reflect", "operationId": "cognitive_cycle",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["agent_pid","input"], "properties": {
                            "agent_pid": { "type": "string", "example": "my-agent" },
                            "input": { "type": "string", "example": "Summarise the user's recent preferences" },
                            "session_id": { "type": "string" },
                            "max_steps": { "type": "integer", "default": 5 }
                        } } } } },
                        "responses": { "200": { "description": "Cycle result with reasoning chain, action taken, reflection" } } }
                },
                "/cognitive/observe": {
                    "post": { "tags": ["Pipeline"], "summary": "Record an observation into the cognitive context", "operationId": "observe",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["agent_pid","observation"], "properties": {
                            "agent_pid": { "type": "string" },
                            "observation": { "type": "string" },
                            "source": { "type": "string", "enum": ["user","tool","environment","memory"] }
                        } } } } },
                        "responses": { "200": { "description": "Observation recorded" } } }
                },
                // ── Safety / Hallucination ─────────────────────────────────────
                "/safety/claims/verify": {
                    "post": { "tags": ["Safety"], "summary": "Verify a claim for hallucination / grounding safety", "operationId": "verify_claim",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["claim"], "properties": {
                            "claim": { "type": "string", "example": "The project uses React for the frontend" },
                            "agent_pid": { "type": "string" },
                            "namespace": { "type": "string" }
                        } } } } },
                        "responses": { "200": { "description": "verdict: Explicit|Implied|Absent, hallucination_safe: bool, confidence: float" } } }
                },
                "/safety/formal/verify": {
                    "get": { "tags": ["Safety"], "summary": "Run all 6 TLA+ formal invariants (Bell-LaPadula, budget, audit chain, etc.)", "operationId": "formal_verify",
                        "responses": { "200": { "description": "Per-invariant pass/fail with violation details" } } }
                },
                "/safety/formal/report": {
                    "get": { "tags": ["Safety"], "summary": "Auditor-facing formal verification report (grade, executive summary)", "operationId": "formal_report",
                        "responses": { "200": { "description": "Report JSON with executive_summary and invariants" } } }
                },
                "/safety/formal/violations": {
                    "get": { "tags": ["Safety"], "summary": "Invariant violations from latest check", "operationId": "formal_violations",
                        "responses": { "200": { "description": "violations array" } } }
                },
                "/safety/formal/snapshot": {
                    "get": { "tags": ["Safety"], "summary": "Raw kernel state snapshot for audit/debug", "operationId": "formal_snapshot",
                        "responses": { "200": { "description": "agents, audit_count, dispatch_count" } } }
                },
                "/grounding/ground-output": {
                    "post": { "tags": ["Safety"], "summary": "Ground LLM output against reference tables (actual path: /grounding/ground-output)", "operationId": "ground_output",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["output"], "properties": {
                            "output": { "type": "string" },
                            "categories": { "type": "array", "items": { "type": "string" }, "example": ["icd10","cpt"] }
                        } } } } },
                        "responses": { "200": { "description": "Grounded output with replaced codes" } } }
                },
                "/grounding/claims/verify": {
                    "post": { "tags": ["Safety"], "summary": "Verify a claim for hallucination / grounding safety", "operationId": "grounding_verify_claim",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["claim"], "properties": {
                            "claim": { "type": "string", "example": "The project uses React for the frontend" },
                            "agent_pid": { "type": "string" },
                            "namespace": { "type": "string" }
                        } } } } },
                        "responses": { "200": { "description": "verdict: Explicit|Implied|Absent, hallucination_safe: bool, confidence: float" } } }
                },
                // ── Protocols ─────────────────────────────────────────────────
                "/protocols/mcp/call": {
                    "post": { "tags": ["Protocols"], "summary": "Call a tool on a connected MCP server", "operationId": "mcp_call",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["server_id","tool_name","arguments"], "properties": {
                            "server_id": { "type": "string", "example": "filesystem-mcp" },
                            "tool_name": { "type": "string", "example": "read_file" },
                            "arguments": { "type": "object", "example": { "path": "/data/report.txt" } },
                            "agent_pid": { "type": "string" }
                        } } } } },
                        "responses": { "200": { "description": "Tool result content" } } }
                },
                "/protocols/a2a/tasks": {
                    "post": { "tags": ["Protocols"], "summary": "Send an A2A task to a remote agent", "operationId": "a2a_send_task",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["agent_card_url","message"], "properties": {
                            "agent_card_url": { "type": "string", "example": "http://agent-b.local/.well-known/agent.json" },
                            "message": { "type": "object" },
                            "from_pid": { "type": "string" }
                        } } } } },
                        "responses": { "200": { "description": "Task ID + initial status" } } }
                },
                "/protocols/a2a/tasks/{task_id}/subscribe": {
                    "get": { "tags": ["Protocols"], "summary": "Subscribe to A2A task progress via SSE", "operationId": "a2a_subscribe_task",
                        "parameters": [
                            { "name": "task_id", "in": "path", "required": true, "schema": { "type": "string" } }
                        ],
                        "responses": {
                            "200": { "description": "SSE stream of task state updates", "content": { "text/event-stream": { "schema": { "type": "string" } } } }
                        } }
                },
                // ── AAPI / Budgets ─────────────────────────────────────────────
                "/aapi/budgets/consume": {
                    "post": { "tags": ["Infra"], "summary": "Consume from an agent's resource budget (tokens, API calls, cost_usd)", "operationId": "consume_budget",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["agent_pid","resource","amount"], "properties": {
                            "agent_pid": { "type": "string", "example": "my-agent" },
                            "resource": { "type": "string", "enum": ["tokens","api_calls","cost_usd"], "example": "tokens" },
                            "amount": { "type": "number", "example": 1500 }
                        } } } } },
                        "responses": { "200": { "description": "Remaining budget" }, "429": { "description": "Budget exhausted" } } }
                },
                "/aapi/capabilities/issue": {
                    "post": { "tags": ["Infra"], "summary": "Issue a UCAN capability token", "operationId": "issue_capability",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["issuer","subject","action","resource"], "properties": {
                            "issuer": { "type": "string" },
                            "subject": { "type": "string" },
                            "action": { "type": "string", "example": "memory:write" },
                            "resource": { "type": "string", "example": "namespace/finance/*" },
                            "expires_in_secs": { "type": "integer", "example": 3600 }
                        } } } } },
                        "responses": { "200": { "description": "Signed UCAN token" } } }
                },
                // ── Infra / Vault ──────────────────────────────────────────────
                "/infra/vault/secrets": {
                    "post": { "tags": ["Infra"], "summary": "Store a secret in the agent vault (returns opaque handle)", "operationId": "vault_store",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["name","value","agent_pid"], "properties": {
                            "name": { "type": "string", "example": "db-password" },
                            "value": { "type": "string", "example": "s3cr3t!" },
                            "agent_pid": { "type": "string" },
                            "ttl_secs": { "type": "integer", "example": 86400 }
                        } } } } },
                        "responses": { "200": { "description": "Opaque handle string" } } }
                },
                "/infra/vault/resolve": {
                    "post": { "tags": ["Infra"], "summary": "Resolve an opaque vault handle to its plaintext value", "operationId": "vault_resolve",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["handle","agent_pid"], "properties": {
                            "handle": { "type": "string", "example": "vault://abc123def456" },
                            "agent_pid": { "type": "string" }
                        } } } } },
                        "responses": { "200": { "description": "Plaintext value (never logged)" } } }
                },
                "/infra/orchestrator/submit": {
                    "post": { "tags": ["Infra"], "summary": "Submit a DAG workflow for execution", "operationId": "submit_dag",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["nodes","edges"], "properties": {
                            "nodes": { "type": "array", "items": { "type": "object" }, "example": [{"id":"A","task":"write_report"},{"id":"B","task":"send_email"}] },
                            "edges": { "type": "array", "items": { "type": "object" }, "example": [{"from":"A","to":"B"}] },
                            "max_retries": { "type": "integer", "default": 3 }
                        } } } } },
                        "responses": { "200": { "description": "Orchestration ID + status" } } }
                },
                // ── Compliance ────────────────────────────────────────────────
                "/compliance/baa/accept": {
                    "post": { "tags": ["Compliance"], "summary": "Accept HIPAA BAA (click-wrap, 30 seconds)", "operationId": "accept_baa",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["org","email"], "properties": {
                            "org": { "type": "string", "example": "Acme Health" },
                            "email": { "type": "string", "format": "email", "example": "cto@acme.com" },
                            "title": { "type": "string", "example": "CTO" }
                        } } } } },
                        "responses": { "200": { "description": "BAA accepted, timestamp + CID returned" } } }
                },
                "/compliance/dpa/accept": {
                    "post": { "tags": ["Compliance"], "summary": "Accept GDPR DPA", "operationId": "accept_dpa",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["org","email"], "properties": {
                            "org": { "type": "string" },
                            "email": { "type": "string", "format": "email" }
                        } } } } },
                        "responses": { "200": { "description": "DPA accepted" } } }
                },
                "/compliance/agreements": {
                    "get": { "tags": ["Compliance"], "summary": "List all accepted legal agreements (BAA, DPA)", "operationId": "list_agreements",
                        "responses": { "200": { "description": "Agreement list with timestamps" } } }
                },
                "/compliance/phi-scan": {
                    "post": { "tags": ["Compliance"], "summary": "Scan text for PHI / PII patterns (HIPAA mode)", "operationId": "phi_scan",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["text"], "properties": {
                            "text": { "type": "string" },
                            "agent_pid": { "type": "string" }
                        } } } } },
                        "responses": { "200": { "description": "Detected PHI entities with positions and types" } } }
                },
                "/compliance/soc2/controls": {
                    "get": { "tags": ["Compliance"], "summary": "SOC2 Type II controls inventory (live status)", "operationId": "soc2_controls",
                        "responses": { "200": { "description": "Controls JSON" } } }
                },
                // ── Deploy ────────────────────────────────────────────────────
                "/deploy": {
                    "post": { "tags": ["Deploy"], "summary": "Deploy an agent manifest", "operationId": "deploy",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["name","spec"], "properties": {
                            "name": { "type": "string", "example": "my-agent" },
                            "spec": { "type": "object", "properties": {
                                "model": { "type": "object", "properties": { "name": { "type": "string", "example": "gpt-4o-mini" } } },
                                "namespace": { "type": "string" },
                                "clearance": { "type": "string" },
                                "resources": { "type": "object" }
                            } }
                        } } } } },
                        "responses": { "200": { "description": "Deploy ID + status" } } }
                },
                "/deploy/validate": {
                    "post": { "tags": ["Deploy"], "summary": "Validate a manifest without deploying", "operationId": "validate_deploy",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["name","spec"] } } } },
                        "responses": { "200": { "description": "Validation result with errors/warnings" } } }
                },
                "/deploy/rollback": {
                    "post": { "tags": ["Deploy"], "summary": "Rollback to a previous deploy revision", "operationId": "rollback",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["name"], "properties": {
                            "name": { "type": "string" },
                            "revision": { "type": "integer", "description": "Revision number to roll back to; defaults to previous" }
                        } } } } },
                        "responses": { "200": { "description": "Rollback complete" } } }
                },
                "/deploy/list": {
                    "get": { "tags": ["Deploy"], "summary": "List all deployed manifests", "operationId": "list_deployed",
                        "responses": { "200": { "description": "Manifest list with revisions" } } }
                },
                "/deploy/history/{name}": {
                    "get": { "tags": ["Deploy"], "summary": "Revision history for a named manifest", "operationId": "deploy_history",
                        "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "responses": { "200": { "description": "Revision list with timestamps and diffs" } } }
                },
                // ── Billing ───────────────────────────────────────────────────
                "/billing/usage": {
                    "get": { "tags": ["Billing"], "summary": "Current token usage, limits, cost, period", "operationId": "billing_usage",
                        "responses": { "200": { "description": "Usage stats" } } }
                },
                "/billing/entitlements": {
                    "get": { "tags": ["Billing"], "summary": "Current plan entitlements (agent limit, features)", "operationId": "billing_entitlements",
                        "responses": { "200": { "description": "Entitlement set" } } }
                },
                "/billing/portal": {
                    "get": { "tags": ["Billing"], "summary": "Stripe Customer Portal (upgrade/cancel/invoices)", "operationId": "billing_portal",
                        "responses": { "302": { "description": "Stripe portal redirect" } } }
                },
                // ── Multiagent ────────────────────────────────────────────────
                "/multiagent/pipelines": {
                    "post": { "tags": ["Multiagent"], "summary": "Create a multi-agent pipeline", "operationId": "create_pipeline",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["agents"], "properties": {
                            "agents": { "type": "array", "items": { "type": "string" }, "example": ["agent-a","agent-b"] },
                            "requires_hitl": { "type": "boolean", "default": false }
                        } } } } },
                        "responses": { "200": { "description": "Pipeline ID" } } }
                },
                "/multiagent/pipelines/{pipeline_id}/approve-step/{step}": {
                    "post": { "tags": ["Multiagent"], "summary": "HITL: approve a pipeline step", "operationId": "approve_step",
                        "parameters": [
                            { "name": "pipeline_id", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "step", "in": "path", "required": true, "schema": { "type": "integer" } }
                        ],
                        "responses": { "200": { "description": "Step approved, pipeline resumes" } } }
                },
                // ── Audit ─────────────────────────────────────────────────────
                "/actionlog/record": {
                    "post": { "tags": ["Audit"], "summary": "Record a custom audit event", "operationId": "record_action",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["agent_pid","action"], "properties": {
                            "agent_pid": { "type": "string" },
                            "action": { "type": "string", "example": "user_data_export" },
                            "outcome": { "type": "string", "enum": ["Allowed","Denied","Skipped"], "default": "Allowed" },
                            "target": { "type": "string" }
                        } } } } },
                        "responses": { "200": { "description": "Audit entry CID" } } }
                },
                "/actionlog/export/otel": {
                    "get": { "tags": ["Audit"], "summary": "Export audit log in OpenTelemetry OTLP format", "operationId": "audit_export_otel",
                        "responses": { "200": { "description": "OTLP-formatted audit log" } } }
                },
                "/actionlog/export/jsonl": {
                    "get": { "tags": ["Audit"], "summary": "Export audit log as newline-delimited JSON", "operationId": "audit_export_jsonl",
                        "parameters": [{ "name": "since_ms", "in": "query", "schema": { "type": "integer" } }],
                        "responses": { "200": { "description": "JSONL audit export" } } }
                },
                // ── Monitor / Infra ───────────────────────────────────────────
                "/monitor/health": {
                    "get": { "tags": ["Monitoring"], "summary": "Platform health check (LLM, DB, kernel status)", "operationId": "platform_health",
                        "responses": { "200": { "description": "Health report" } } }
                },
                "/monitor/trust": {
                    "get": { "tags": ["Monitoring"], "summary": "Current platform trust score (0–100)", "operationId": "trust_score",
                        "responses": { "200": { "description": "Trust score with grade and sub-scores" } } }
                },
                "/monitor/grafana-dashboard": {
                    "get": { "tags": ["Monitoring"], "summary": "Import-ready Grafana dashboard JSON (matches deploy/grafana/connector-dashboard.json)", "operationId": "grafana_dashboard",
                        "responses": { "200": { "description": "Grafana JSON — paste into Grafana Import" } } }
                },
                "/proof/generate": {
                    "post": { "tags": ["Proof"], "summary": "Generate a trust certificate for an agent", "operationId": "generate_proof",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["agent_pid"], "properties": {
                            "agent_pid": { "type": "string" },
                            "include_audit_chain": { "type": "boolean", "default": true }
                        } } } } },
                        "responses": { "200": { "description": "Signed trust certificate with Ed25519 signature" } } }
                },
                "/docs/migration": {
                    "get": { "tags": ["Docs"], "summary": "Route migration guide — old vs new paths, gateway base URL, SDK examples", "operationId": "migration_guide",
                        "responses": { "200": { "description": "Migration guide JSON" } }, "security": [] }
                },
                // ── Gateway (separate base URL /v1) ───────────────────────────
                "/v1/chat/completions": {
                    "post": { "tags": ["Gateway"], "summary": "OpenAI-compatible LLM proxy (base_url=/v1, NOT /api/v1)", "operationId": "chat_completions",
                        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["model","messages"], "properties": {
                            "model": { "type": "string", "example": "gpt-4o-mini" },
                            "messages": { "type": "array", "items": { "type": "object", "properties": { "role": { "type": "string" }, "content": { "type": "string" } } } },
                            "stream": { "type": "boolean", "default": false },
                            "temperature": { "type": "number", "default": 0.7 }
                        } } } } },
                        "responses": { "200": { "description": "OpenAI-compatible ChatCompletion response" }, "403": { "description": "Injection detected or budget exhausted" } },
                        "servers": [{ "url": "http://localhost:8080", "description": "Gateway root (no /api/v1 prefix)" }] }
                },
                "/v1/models": {
                    "get": { "tags": ["Gateway"], "summary": "List available models", "operationId": "list_models",
                        "responses": { "200": { "description": "OpenAI-compatible model list" } },
                        "servers": [{ "url": "http://localhost:8080", "description": "Gateway root" }] }
                },
                // ── Surfaces (SOE) ───────────────────────────────────────────
                "/surfaces/{surface}/{subject_id}": {
                    "get": { "tags": ["Surfaces"], "summary": "Rendered SOE surface JSON — role-aware, paginated, searchable", "operationId": "render_surface",
                        "parameters": [
                            { "name": "surface", "in": "path", "required": true, "schema": { "type": "string", "enum": ["agent","audit","memory","knowledge","policy","tool","contract","proof","compliance","health","books","debug","trace","inspect","review","explain","monitor"] }, "description": "Surface type" },
                            { "name": "subject_id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Subject identifier (agent PID, resource key, etc.)" },
                            { "name": "view", "in": "query", "schema": { "type": "string", "enum": ["summary","ops","forensic","exec"] }, "description": "View mode (defaults to role's preferred view)" },
                            { "name": "time", "in": "query", "schema": { "type": "string" }, "description": "Time selector (now, @<ts>, since:<ts>, last:15m, etc.)" },
                            { "name": "page", "in": "query", "schema": { "type": "integer", "default": 1 } },
                            { "name": "page_size", "in": "query", "schema": { "type": "integer", "default": 50 } },
                            { "name": "search", "in": "query", "schema": { "type": "string" } },
                            { "name": "filter", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "description": "Repeatable filter expressions (field=value)" },
                            { "name": "sort", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "description": "Sort expressions (-field or field:asc)" }
                        ],
                        "responses": {
                            "200": { "description": "SOE JSON envelope with _meta, surface_contract, document, optional query/page_info" },
                            "400": { "description": "Invalid surface/view/time/query parameter" },
                            "401": { "description": "Missing or invalid auth" },
                            "403": { "description": "Policy denied for requested view" },
                            "404": { "description": "Subject not found" },
                            "422": { "description": "Contract validation failed (server bug)" },
                            "500": { "description": "Internal error" }
                        }
                    }
                },
                // ── Infrastructure ────────────────────────────────────────────
                "/health": { "get": { "tags": ["Monitoring"], "summary": "Health check (always 200 if process is up)", "operationId": "health", "responses": { "200": { "description": "OK" } }, "security": [] } },
                "/ready": { "get": { "tags": ["Monitoring"], "summary": "Readiness check (200 when DB + kernel ready)", "operationId": "ready", "responses": { "200": { "description": "Ready" }, "503": { "description": "Not ready" } }, "security": [] } },
                "/metrics": { "get": { "tags": ["Monitoring"], "summary": "Prometheus metrics", "operationId": "metrics", "responses": { "200": { "description": "Prometheus text/plain format" } } } },
                "/healthz": { "get": { "tags": ["Monitoring"], "summary": "Liveness probe (always 200)", "operationId": "healthz", "responses": { "200": { "description": "ok: true" } }, "security": [] } },
                "/readyz": { "get": { "tags": ["Monitoring"], "summary": "Readiness probe (503 when not ready)", "operationId": "readyz", "responses": { "200": { "description": "Ready" }, "503": { "description": "Not ready" } }, "security": [] } },
                "/version": { "get": { "tags": ["Monitoring"], "summary": "Build version + commit metadata", "operationId": "version", "responses": { "200": { "description": "Version JSON" } }, "security": [] } }
            }
        })
}

/// GET /openapi.json — OpenAPI 3.1 spec for all API routes.
async fn openapi_spec() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        openapi_spec_value().to_string(),
    )
}

/// GET /docs — Swagger UI (rendered in browser, points to /openapi.json).
async fn swagger_ui() -> impl IntoResponse {
    let html = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Connector Platform API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; }
    #swagger-ui .topbar { background: #1a1a2e; }
    #swagger-ui .topbar-wrapper .link { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      SwaggerUIBundle({
        url: "/openapi.json",
        dom_id: "#swagger-ui",
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
        layout: "BaseLayout",
        deepLinking: true,
        displayRequestDuration: true,
        tryItOutEnabled: true,
        persistAuthorization: true,
        requestInterceptor: (req) => {
          const key = localStorage.getItem("connector_api_key");
          if (key && !req.headers["Authorization"]) req.headers["Authorization"] = "Bearer " + key;
          return req;
        }
      });
    };
  </script>
</body>
</html>"##;

    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
}

// ── Route migration guide ─────────────────────────────────────────────────────

async fn migration_guide() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "title": "Connector Platform — Route Migration Guide",
        "version": "0.2.0 → 1.0.0",
        "docs": "https://connector.dev/docs/migration",
        "summary": "All deprecated routes below ACTUALLY emit `Deprecated: true`, `Sunset: 1.0.0`, and `Link: <canonical>; rel=successor-version` response headers on every response. This is enforced at the Axum router layer via with_deprecation_headers(), not just in documentation.",
        "migrations": [
            {
                "old": "GET /api/v1/memory/recall2/:namespace",
                "new": "GET /api/v1/memory/recall/:namespace",
                "reason": "Suffix versioning removed from public API. The canonical path now serves the full memory2 handler (session_id, time_range, packet_type filters all supported).",
                "deprecated_since": "0.3.0",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "old": "POST /api/v1/memory/knowledge/query2",
                "new": "POST /api/v1/memory/knowledge/query",
                "reason": "Suffix versioning removed. Canonical path now serves full RAG handler with time_range and grounding.",
                "deprecated_since": "0.3.0",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "old": "GET /api/v1/memory/interference2/:agent_pid",
                "new": "GET /api/v1/memory/interference/:agent_pid",
                "reason": "Suffix versioning removed. Canonical path now serves real StateVector computation.",
                "deprecated_since": "0.3.0",
                "wire_deprecated": true,
                "will_remove": "1.0.0"
            },
            {
                "old": "POST /api/v1/secrets/store",
                "new": "POST /api/v1/infra/vault/secrets",
                "reason": "Canonical vault lives under /infra for consistency with consensus/reputation/orchestrator",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "POST /api/v1/secrets/resolve",
                "new": "POST /api/v1/infra/vault/resolve",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "POST /api/v1/orchestrator/dag",
                "new": "POST /api/v1/infra/orchestrator/submit",
                "reason": "Canonical DAG orchestrator under /infra; /orchestrator/* is a duplicate",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "GET /api/v1/orchestrator/dag/:id",
                "new": "GET /api/v1/infra/orchestrator/:orch_id",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "GET /api/v1/economy/reputation/scores",
                "new": "GET /api/v1/infra/reputation/scores",
                "reason": "Canonical EigenTrust reputation under /infra",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "POST /api/v1/economy/reputation/feedback",
                "new": "POST /api/v1/infra/reputation/feedback",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "GET /api/v1/verify/invariants",
                "new": "GET /api/v1/safety/formal/verify",
                "reason": "Formal verification merged into safety service",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "POST /api/v1/legal/baa/accept",
                "new": "POST /api/v1/compliance/baa/accept",
                "reason": "Consolidated under compliance service",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            },
            {
                "old": "POST /api/v1/legal/dpa/accept",
                "new": "POST /api/v1/compliance/dpa/accept",
                "deprecated_since": "0.2.0",
                "will_remove": "1.0.0"
            }
        ],
        "gateway_note": {
            "message": "The AI Gateway does NOT live under /api/v1/. It uses a separate base URL.",
            "correct_base_url": "/v1",
            "example": "POST /v1/chat/completions  (not /api/v1/v1/chat/completions)",
            "openai_sdk": "OpenAI(base_url='http://localhost:8080/v1', api_key='cpk_...')"
        }
    }))
}

// ── Legal → Compliance redirect handlers ─────────────────────────────────────

async fn legal_redirect_baa(
    axum::extract::State(state): axum::extract::State<SharedState>,
    headers: axum::http::HeaderMap,
    body: axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    // Forward to compliance handler and add deprecation headers
    let result = services::compliance::baa_accept(
        axum::extract::State(state),
        headers,
        body,
    ).await;
    let mut resp = result.into_response();
    let h = resp.headers_mut();
    h.insert("Deprecated", axum::http::HeaderValue::from_static("true"));
    h.insert("Link", axum::http::HeaderValue::from_static(
        "</api/v1/compliance/baa/accept>; rel=\"successor-version\""
    ));
    h.insert("Sunset", axum::http::HeaderValue::from_static("1.0.0"));
    resp
}

async fn legal_redirect_dpa(
    axum::extract::State(state): axum::extract::State<SharedState>,
    headers: axum::http::HeaderMap,
    body: axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    let result = services::compliance::dpa_accept(
        axum::extract::State(state),
        headers,
        body,
    ).await;
    let mut resp = result.into_response();
    let h = resp.headers_mut();
    h.insert("Deprecated", axum::http::HeaderValue::from_static("true"));
    h.insert("Link", axum::http::HeaderValue::from_static(
        "</api/v1/compliance/dpa/accept>; rel=\"successor-version\""
    ));
    h.insert("Sunset", axum::http::HeaderValue::from_static("1.0.0"));
    resp
}

async fn legal_redirect_agreements(
    axum::extract::State(state): axum::extract::State<SharedState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let result = services::compliance::list_agreements(
        axum::extract::State(state),
        headers,
    ).await;
    let mut resp = result.into_response();
    let h = resp.headers_mut();
    h.insert("Deprecated", axum::http::HeaderValue::from_static("true"));
    h.insert("Link", axum::http::HeaderValue::from_static(
        "</api/v1/compliance/agreements>; rel=\"successor-version\""
    ));
    h.insert("Sunset", axum::http::HeaderValue::from_static("1.0.0"));
    resp
}

/// GET /api/v1/internal/dns — dump the in-process InternalDns service registry.
/// Shows registered service names, bound addresses, health, and tags.
/// Useful for debugging port assignments and verifying gateway startup.
async fn internal_dns_handler() -> impl IntoResponse {
    let entries = crate::internal_dns::dump_json();
    let count = entries.len();
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_string(&serde_json::json!({
            "services": entries,
            "count": count,
        })).unwrap_or_else(|_| "{}".to_string()),
    )
}
