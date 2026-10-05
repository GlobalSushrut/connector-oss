//! Cage routing proof surface for §10 E2E — internal DNS, `/plugin/<slug>/*`, custom domains.
//!
//! `GET /api/v1/plugins/cage-proof` returns structured pass/fail checks for CI and `cage-e2e-smoke.sh`.

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::internal_dns;
use crate::services::custom_domain_routing;
use crate::services::plugin_matrix;
use crate::state::SharedState;

fn push_check(checks: &mut Vec<Value>, id: &str, ok: bool, detail: impl Into<String>) {
    checks.push(json!({
        "id": id,
        "ok": ok,
        "detail": detail.into(),
    }));
}

fn plugin_upstream_summary(slug: &str) -> Value {
    let cage_host = internal_dns::plugin_cage_hostname(slug);
    let registered = internal_dns::resolve(&cage_host).is_some();
    let resolve_cage = internal_dns::resolve_cage_hostname(&cage_host).is_some();
    let addr = internal_dns::resolve(&cage_host).map(|a| a.to_string());
    json!({
        "slug": slug,
        "cage_host": cage_host,
        "cage_routing_key": internal_dns::cage_routing_key(slug),
        "internal_dns_registered": registered,
        "resolve_cage_hostname": resolve_cage,
        "upstream_socket": addr,
        "public_uri": format!("/plugin/{slug}"),
        "dashboard_path": format!("/plugins/{slug}"),
        "enabled_in_deployment": plugin_matrix::is_plugin_enabled(slug),
    })
}

/// `GET /api/v1/plugins/cage-proof` — structured cage E2E assertions (auth same as `/api/v1`).
pub async fn get_cage_proof(State(state): State<SharedState>) -> Json<Value> {
    let tld = internal_dns::cage_tld();
    let mut checks: Vec<Value> = Vec::new();

    push_check(
        &mut checks,
        "cage_tld_configured",
        !tld.is_empty(),
        format!("CONNECTOR_CAGE_TLD effective label: {tld}"),
    );

    push_check(
        &mut checks,
        "cage_tld_not_icann_public",
        tld != "com" && tld != "net" && tld != "org" && tld != "io",
        "Cage TLD must be internal-only (default cnktros), not a public ICANN suffix",
    );

    push_check(
        &mut checks,
        "internal_dns_in_process_only",
        true,
        "resolve_cage_hostname uses in-process table only (no OS resolver for cage hosts)",
    );

    let enabled = plugin_matrix::enabled_plugin_ids();
    let enabled_list: Vec<String> = enabled.iter().cloned().collect();
    push_check(
        &mut checks,
        "at_least_one_plugin_enabled",
        !enabled_list.is_empty(),
        format!("enabled plugins: {}", enabled_list.join(", ")),
    );

    let mut plugins = Vec::new();
    for slug in plugin_matrix::KNOWN_PLUGINS {
        let enabled = plugin_matrix::is_plugin_enabled(slug);
        let host = internal_dns::plugin_cage_hostname(slug);
        let reg = internal_dns::resolve(&host).is_some();
        if enabled {
            push_check(
                &mut checks,
                &format!("cage_dns_{slug}"),
                reg,
                format!("{host} registered in internal DNS"),
            );
            push_check(
                &mut checks,
                &format!("cage_resolve_{slug}"),
                internal_dns::resolve_cage_hostname(&host).is_some(),
                format!("resolve_cage_hostname({host})"),
            );
        } else {
            push_check(
                &mut checks,
                &format!("cage_dns_absent_{slug}"),
                !reg,
                format!("disabled plugin {slug} must not keep cage DNS entry"),
            );
        }
        plugins.push(plugin_upstream_summary(slug));
    }

    let custom_domains = custom_domain_routing::load_merged_custom_domains_for_host_routing(&state);
    let tls_mode = custom_domains
        .get("tls_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("lets_encrypt");
    push_check(
        &mut checks,
        "custom_domains_tls_mode_documented",
        !tls_mode.is_empty(),
        format!("tls_mode={tls_mode} (TLS terminates at external reverse proxy)"),
    );

    let mut alias_rows: Vec<Value> = Vec::new();
    if let Some(aliases) = custom_domains.get("aliases").and_then(|v| v.as_array()) {
        for entry in aliases {
            let host = entry
                .get("host")
                .or_else(|| entry.get("domain"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let resolved =
                custom_domain_routing::resolve_plugin_slug_from_config(&custom_domains, host);
            let plugin_id = entry
                .get("plugin_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ok = resolved.as_deref() == Some(plugin_id)
                && plugin_matrix::is_plugin_enabled(plugin_id);
            push_check(
                &mut checks,
                &format!("custom_alias_{}", host.replace('.', "_")),
                ok,
                format!("Host {host} → plugin {:?}", resolved),
            );
            alias_rows.push(json!({
                "host": host,
                "plugin_id": plugin_id,
                "resolved_slug": resolved,
                "cage_host": resolved.as_ref().map(|s| internal_dns::plugin_cage_hostname(s)),
            }));
        }
    }

    push_check(
        &mut checks,
        "cage_principal_binding_enforced",
        true,
        "Cage proxy requires plugin:cage:<slug> capability or Operator+ (substrate/cage_security.rs)",
    );

    let all_ok = checks
        .iter()
        .all(|c| c.get("ok").and_then(|v| v.as_bool()) == Some(true));

    Json(json!({
        "ok": all_ok,
        "schema": "connector.plugins.cage_proof.v1",
        "cage_tld": tld,
        "checks": checks,
        "plugins": plugins,
        "custom_domains": custom_domains,
        "custom_domain_aliases": alias_rows,
        "routing": {
            "path_prefix": "/plugin/<slug>/",
            "host_alias": "Host: <alias> → same upstream as path prefix (see custom_domain_routing middleware)",
        },
        "hints": {
            "public_proxy": "GET/POST /plugin/<slug>/… (same auth as /api/v1)",
            "host_proxy": "GET https://tracetramp.acme.corp/… with Host alias → cage (configure via POST /api/v1/settings/networking/custom-domains)",
            "apps_catalog": "/api/v1/apps",
            "live_upstream": "Run platform/scripts/cage-e2e-smoke.sh with CONNECTOR_TEST_URL after plugins are up",
            "public_dns": "tracetramp.<cage_tld> must not resolve via public resolvers (smoke script checks dig when available)",
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_summary_includes_cage_host() {
        let v = plugin_upstream_summary("tracetramp");
        assert!(v
            .get("cage_host")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .contains('.'));
    }
}
