//! Custom public domain → plugin cage routing (T6 / roadmap §2E).
//!
//! Operators configure aliases in Settings → Networking (`custom_domains` blob). Requests whose
//! `Host` matches an alias are proxied to the same upstream as `/plugin/<slug>/…` without requiring
//! the `/plugin/` path prefix (e.g. `https://tracetramp.acme.corp/admin/stats` → `tracetramp.cnktros`).

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::internal_dns;
use crate::services::plugin_cage_proxy;
use crate::services::plugin_matrix;
use crate::state::SharedState;

const SETTINGS_FOLDER: &str = "settings_system";
const CUSTOM_DOMAINS_KEY: &str = "custom_domains";

/// Engine-store key for tenant-scoped custom domain config (`custom_domains` = default tenant).
pub fn custom_domains_settings_key(tenant_id: Option<&str>) -> String {
    match tenant_id.filter(|t| !t.is_empty() && *t != "default") {
        Some(t) => format!("{CUSTOM_DOMAINS_KEY}:{t}"),
        None => CUSTOM_DOMAINS_KEY.to_string(),
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or(host)
        .to_ascii_lowercase()
}

pub fn load_custom_domains_config(state: &SharedState, tenant_id: Option<&str>) -> Value {
    let key = custom_domains_settings_key(tenant_id);
    let es = state.engine_store.lock().unwrap();
    es.folder_get(SETTINGS_FOLDER, &key)
        .ok()
        .flatten()
        .unwrap_or(Value::Null)
}

/// Hosts configured for a plugin across all alias entries in `cfg`.
pub fn custom_domain_hosts_for_plugin(cfg: &Value, plugin_id: &str) -> Vec<String> {
    let want = plugin_id.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    let Some(aliases) = cfg.get("aliases").and_then(|v| v.as_array()) else {
        return out;
    };
    for entry in aliases {
        if entry.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }
        let slug = entry
            .get("plugin_id")
            .or_else(|| entry.get("plugin"))
            .or_else(|| entry.get("slug"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if slug != want {
            continue;
        }
        if let Some(host) = entry
            .get("host")
            .or_else(|| entry.get("domain"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            if !out.iter().any(|h| h == &host) {
                out.push(host);
            }
        }
    }
    out
}

/// Merge alias tables from default + `custom_domains:<tenant>` keys for Host-based cage routing.
pub fn load_merged_custom_domains_for_host_routing(state: &SharedState) -> Value {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(SETTINGS_FOLDER, None).unwrap_or_default();
    let mut aliases: Vec<Value> = Vec::new();
    let mut tls_mode = "lets_encrypt".to_string();
    for key in keys {
        if key != CUSTOM_DOMAINS_KEY && !key.starts_with(&format!("{CUSTOM_DOMAINS_KEY}:")) {
            continue;
        }
        let Some(v) = es.folder_get(SETTINGS_FOLDER, &key).ok().flatten() else {
            continue;
        };
        if let Some(mode) = v.get("tls_mode").and_then(|x| x.as_str()) {
            if !mode.is_empty() {
                tls_mode = mode.to_string();
            }
        }
        if let Some(arr) = v.get("aliases").and_then(|x| x.as_array()) {
            aliases.extend(arr.iter().cloned());
        }
    }
    json!({
        "aliases": aliases,
        "tls_mode": tls_mode,
    })
}

/// Resolve plugin slug from `Host` using a `custom_domains` config object.
pub fn resolve_plugin_slug_from_config(cfg: &Value, host: &str) -> Option<String> {
    let host = normalize_host(host);
    if host.is_empty() {
        return None;
    }

    if let Some(aliases) = cfg.get("aliases").and_then(|v| v.as_array()) {
        for entry in aliases {
            let alias_host = entry
                .get("host")
                .or_else(|| entry.get("domain"))
                .and_then(|v| v.as_str())
                .map(normalize_host);
            let Some(alias_host) = alias_host else {
                continue;
            };
            if alias_host != host {
                continue;
            }
            if entry.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
                continue;
            }
            let slug = entry
                .get("plugin_id")
                .or_else(|| entry.get("plugin"))
                .or_else(|| entry.get("slug"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty());
            if let Some(slug) = slug {
                if plugin_matrix::is_gated_plugin_segment(&slug)
                    && plugin_matrix::is_plugin_enabled(&slug)
                {
                    return Some(slug);
                }
            }
        }
    }

    if internal_dns::is_cage_host(&host) {
        let tld = internal_dns::cage_tld();
        let suffix = format!(".{tld}");
        if let Some(slug) = host.strip_suffix(&suffix) {
            let slug = slug.to_ascii_lowercase();
            if plugin_matrix::is_gated_plugin_segment(&slug)
                && plugin_matrix::is_plugin_enabled(&slug)
            {
                return Some(slug);
            }
        }
    }

    None
}

/// Resolve plugin slug from `Host` — custom alias table, then direct cage hostname (`slug.cnktros`).
pub fn resolve_plugin_slug_for_host(state: &SharedState, host: &str) -> Option<String> {
    resolve_plugin_slug_from_config(&load_merged_custom_domains_for_host_routing(state), host)
}

/// Validate `aliases` shape on save (admin API).
pub fn validate_custom_domains_value(value: &Value) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let Some(obj) = value.as_object() else {
        return Err("custom_domains must be a JSON object".into());
    };
    if let Some(aliases) = obj.get("aliases") {
        let arr = aliases
            .as_array()
            .ok_or_else(|| "aliases must be an array".to_string())?;
        for (i, entry) in arr.iter().enumerate() {
            let host = entry
                .get("host")
                .or_else(|| entry.get("domain"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let slug = entry
                .get("plugin_id")
                .or_else(|| entry.get("plugin"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty());
            if host.is_none() || slug.is_none() {
                return Err(format!("aliases[{i}] requires host/domain and plugin_id"));
            }
            let slug = slug.unwrap();
            if !plugin_matrix::is_gated_plugin_segment(&slug) {
                return Err(format!("aliases[{i}] unknown plugin_id {slug}"));
            }
            if internal_dns::is_cage_host(host.unwrap()) {
                return Err(format!(
                    "aliases[{i}] must be a public hostname, not a cage internal name"
                ));
            }
        }
    }
    if let Some(mode) = obj.get("tls_mode").and_then(|v| v.as_str()) {
        let m = mode.trim().to_ascii_lowercase();
        if !matches!(
            m.as_str(),
            "lets_encrypt" | "lets-encrypt" | "manual" | "off" | "terminator"
        ) {
            return Err(format!("unsupported tls_mode: {mode}"));
        }
    }
    Ok(())
}

fn save_custom_domains_config(state: &SharedState, cfg: &Value) -> Result<(), String> {
    validate_custom_domains_value(cfg)?;
    let mut es = state.engine_store.lock().unwrap();
    es.folder_put(SETTINGS_FOLDER, CUSTOM_DOMAINS_KEY, cfg)
        .map_err(|e| format!("store failed: {e}"))
}

/// Upsert a host alias into the default tenant `custom_domains` blob (edge plane write path).
pub fn upsert_custom_domain_alias(
    state: &SharedState,
    host: &str,
    plugin_id: &str,
    enabled: bool,
) -> Result<Value, String> {
    let host = host.trim();
    let slug = plugin_id.trim().to_ascii_lowercase();
    if host.is_empty() || slug.is_empty() {
        return Err("host and plugin_id required".into());
    }
    let mut cfg = load_custom_domains_config(state, None);
    if cfg.is_null() {
        cfg = json!({
            "aliases": [],
            "tls_mode": "lets_encrypt",
        });
    } else if cfg.get("aliases").and_then(|v| v.as_array()).is_none() {
        if let Some(obj) = cfg.as_object_mut() {
            obj.insert("aliases".into(), json!([]));
        }
    }
    let aliases = cfg
        .as_object_mut()
        .and_then(|o| o.get_mut("aliases"))
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "custom_domains.aliases must be an array".to_string())?;
    let entry = json!({
        "host": host,
        "plugin_id": slug,
        "enabled": enabled,
    });
    if let Some(pos) = aliases.iter().position(|e| {
        e.get("host")
            .or_else(|| e.get("domain"))
            .and_then(|v| v.as_str())
            == Some(host)
    }) {
        aliases[pos] = entry;
    } else {
        aliases.push(entry);
    }
    save_custom_domains_config(state, &cfg)?;
    Ok(cfg)
}

/// Remove alias by edge record id `custom_domain:{slug}:{host}`.
pub fn remove_custom_domain_by_record_id(
    state: &SharedState,
    record_id: &str,
) -> Result<bool, String> {
    let parts: Vec<&str> = record_id.trim().split(':').collect();
    if parts.len() < 3 || parts[0] != "custom_domain" {
        return Err("record id must be custom_domain:{plugin_id}:{host}".into());
    }
    let slug = parts[1];
    let host = parts[2..].join(":");
    let mut cfg = load_custom_domains_config(state, None);
    let Some(aliases) = cfg.get_mut("aliases").and_then(|v| v.as_array_mut()) else {
        return Ok(false);
    };
    let before = aliases.len();
    aliases.retain(|e| {
        let h = e
            .get("host")
            .or_else(|| e.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let s = e
            .get("plugin_id")
            .or_else(|| e.get("plugin"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        !(h == host && s == slug)
    });
    if aliases.len() == before {
        return Ok(false);
    }
    save_custom_domains_config(state, &cfg)?;
    Ok(true)
}

/// Host-based cage proxy — runs on the outer router before SPA fallback.
pub async fn custom_domain_cage_middleware(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if path.starts_with("/api/")
        || path.starts_with("/plugin/")
        || path.starts_with("/v1/")
        || path.starts_with("/docs")
        || path.starts_with("/openapi")
        || path == "/health"
        || path == "/healthz"
        || path == "/readyz"
        || path == "/metrics"
    {
        return next.run(req).await;
    }

    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(normalize_host);

    let Some(host) = host else {
        return next.run(req).await;
    };

    let Some(slug) = resolve_plugin_slug_for_host(&state, &host) else {
        return next.run(req).await;
    };

    let tail = path.trim_start_matches('/');
    let mut path_and_query = if tail.is_empty() {
        format!("/plugin/{slug}/")
    } else {
        format!("/plugin/{slug}/{tail}")
    };
    if let Some(q) = req.uri().query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }

    let Ok(uri) = path_and_query.parse::<Uri>() else {
        return next.run(req).await;
    };

    if !crate::services::runtime_control::operator_lab_auth_gate(
        *state.runtime_mode.read().unwrap(),
    ) {
        let token = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        let authed = if token.starts_with("cpk_") {
            crate::auth::validate_api_key(token).is_ok()
        } else if !token.is_empty() {
            crate::auth::verify_token(token).is_ok()
        } else {
            false
        };
        if !authed {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "authentication_required",
                        "message": "Custom domain cage proxy requires Authorization (same as /plugin/<slug>)",
                        "status": 401
                    }
                })),
            )
                .into_response();
        }
    }

    let (parts, body) = req.into_parts();
    let mut inner = Request::from_parts(parts, body);
    *inner.uri_mut() = uri;

    plugin_cage_proxy::plugin_cage_forward(
        State(state),
        inner.uri().clone(),
        inner.method().clone(),
        inner.headers().clone(),
        inner.into_body(),
    )
    .await
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_custom_alias() {
        std::env::set_var(
            "CONNECTOR_PLUGINS_ENABLED",
            "tracetramp,witnessctl,devguard",
        );
        let cfg = serde_json::json!({
            "aliases": [
                {"host": "tracetramp.acme.corp", "plugin_id": "tracetramp", "enabled": true},
            ],
        });
        let slug = resolve_plugin_slug_from_config(&cfg, "tracetramp.acme.corp");
        assert_eq!(slug.as_deref(), Some("tracetramp"));
        std::env::remove_var("CONNECTOR_PLUGINS_ENABLED");
    }

    #[test]
    fn custom_domains_key_scopes_tenant() {
        assert_eq!(
            custom_domains_settings_key(Some("acme")),
            "custom_domains:acme"
        );
        assert_eq!(custom_domains_settings_key(None), "custom_domains");
        assert_eq!(
            custom_domains_settings_key(Some("default")),
            "custom_domains"
        );
    }

    #[test]
    fn hosts_for_plugin_filters_enabled() {
        let cfg = serde_json::json!({
            "aliases": [
                {"host": "tt.acme.corp", "plugin_id": "tracetramp", "enabled": true},
                {"host": "tt-old.acme.corp", "plugin_id": "tracetramp", "enabled": false},
                {"host": "wc.acme.corp", "plugin_id": "witnessctl", "enabled": true},
            ],
        });
        let hosts = custom_domain_hosts_for_plugin(&cfg, "tracetramp");
        assert_eq!(hosts, vec!["tt.acme.corp".to_string()]);
    }

    #[test]
    fn validate_rejects_cage_host_as_alias() {
        std::env::set_var("CONNECTOR_PLUGINS_ENABLED", "tracetramp");
        let cfg = serde_json::json!({
            "aliases": [{"host": "tracetramp.cnktros", "plugin_id": "tracetramp"}],
        });
        assert!(validate_custom_domains_value(&cfg).is_err());
        std::env::remove_var("CONNECTOR_PLUGINS_ENABLED");
    }
}
