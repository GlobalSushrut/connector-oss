//! Phase 4.8 — plugin marketplace detail (README, capabilities, versions, signing, stats).

use std::collections::BTreeMap;
use std::path::Path;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth;
use crate::services::hub_mirrors::hub_mirror_bases;
use crate::services::plugin_cpkg::safe_plugin_id;
use crate::services::plugin_lifecycle::load_plugin_lifecycle_state;
use crate::services::runtime_control;
use crate::state::SharedState;
use connector_plugin_manifest::PluginManifest;

const STATS_FOLDER: &str = "plugin_marketplace_stats";

#[derive(Debug, Deserialize)]
pub struct MarketplaceQuery {
    pub plugin_id: String,
}

fn require_auth_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    Err(json!({"ok": false, "error": "Unauthorized"}))
}

fn local_install_count(state: &SharedState, plugin_id: &str) -> u64 {
    let sid = safe_plugin_id(plugin_id);
    let es = state.engine_store.lock().unwrap();
    es.folder_get(STATS_FOLDER, &sid)
        .ok()
        .flatten()
        .and_then(|v| v.get("local_install_count").and_then(|x| x.as_u64()))
        .unwrap_or(0)
}

fn store_root(state: &SharedState) -> std::path::PathBuf {
    Path::new(&state.config.data_dir)
        .join("plugins")
        .join("cpkg_store")
}

fn read_manifest_from_dir(files_dir: &Path) -> Option<PluginManifest> {
    let p = files_dir.join("plugin.toml");
    let raw = std::fs::read_to_string(p).ok()?;
    PluginManifest::parse(&raw).ok()
}

fn read_manifest_from_cpkg(pkg_path: &Path) -> Option<PluginManifest> {
    let bytes = std::fs::read(pkg_path).ok()?;
    connector_cpkg::read_cpkg(&bytes).ok().map(|b| b.manifest)
}

fn readme_snippet(files_dir: &Path) -> Option<String> {
    for name in ["README.md", "readme.md", "Readme.md"] {
        let p = files_dir.join(name);
        if let Ok(s) = std::fs::read_to_string(p) {
            return Some(s.chars().take(12_000).collect());
        }
    }
    None
}

fn signing_fingerprint(manifest: &PluginManifest, pkg_path: Option<&Path>) -> Value {
    let mut v = json!({});
    if let Some(ref s) = manifest.signing {
        v["manifest_pubkey"] = json!(s.pubkey);
    }
    if let Some(path) = pkg_path {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(bundle) = connector_cpkg::read_cpkg(&bytes) {
                if let Some(sig) = bundle.signature {
                    v["cpkg_signature"] = json!({
                        "algorithm": sig.algorithm,
                        "key_id": sig.key_id,
                        "payload_sha256": sig.payload_sha256,
                        "parent_key_id": sig.parent_key_id,
                    });
                }
            }
        }
    }
    v
}

async fn hub_index_rows_for_plugin(state: &SharedState, plugin_id: &str) -> Vec<Value> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let q = urlencoding::encode(plugin_id);
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    for base in hub_mirror_bases(state).iter().take(6) {
        let url = format!("{}/v1/search?q={}", base.trim_end_matches('/'), q);
        if crate::substrate::egress_policy::assert_safe_outbound_url(&url).is_err() {
            continue;
        }
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(j) = resp.json::<Value>().await else {
            continue;
        };
        let Some(pkgs) = j.get("packages").and_then(|x| x.as_array()) else {
            continue;
        };
        for p in pkgs {
            let vid = p
                .get("plugin_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let ver = p
                .get("version")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if vid == plugin_id && !ver.is_empty() {
                merged.entry(ver).or_insert_with(|| p.clone());
            }
        }
    }
    merged.into_values().collect()
}

pub async fn get_plugin_marketplace(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<MarketplaceQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_auth_or_dev(&headers) {
        return Err((StatusCode::UNAUTHORIZED, Json(e)));
    }
    let plugin_id = q.plugin_id.trim().to_string();
    if plugin_id.is_empty() || plugin_id.split('/').count() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "plugin_id must be vendor/slug"})),
        ));
    }

    let life = load_plugin_lifecycle_state(&state, &plugin_id);
    let sid = safe_plugin_id(&plugin_id);
    let root = store_root(&state).join(&sid);
    let versions_dir = root.join("versions");

    let mut versions: Vec<Value> = Vec::new();
    if versions_dir.is_dir() {
        let mut ents: Vec<String> = std::fs::read_dir(&versions_dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        ents.sort_by(
            |a, b| match (semver::Version::parse(a), semver::Version::parse(b)) {
                (Ok(va), Ok(vb)) => vb.cmp(&va),
                _ => b.cmp(a),
            },
        );

        for ver in ents {
            let vdir = versions_dir.join(&ver);
            let files_dir = vdir.join("files");
            let pkg_path = vdir.join("package.cpkg");
            let manifest =
                read_manifest_from_dir(&files_dir).or_else(|| read_manifest_from_cpkg(&pkg_path));
            let readme = readme_snippet(&files_dir);
            let caps = manifest.as_ref().map(|m| json!(m.capabilities.required));
            versions.push(json!({
                "version": ver,
                "capabilities": caps,
                "readme_preview": readme,
                "has_package": pkg_path.exists(),
            }));
        }
    }

    let rollout_path = root.join("rollout.json");
    let active_version = std::fs::read_to_string(&rollout_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| {
            v.get("active_version")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        });

    let hub_rows = hub_index_rows_for_plugin(&state, &plugin_id).await;
    let hub_install_total: u64 = hub_rows
        .iter()
        .filter_map(|r| r.get("install_count").and_then(|x| x.as_u64()))
        .sum();
    let rating_samples: Vec<f64> = hub_rows
        .iter()
        .filter_map(|r| r.get("avg_rating").and_then(|x| x.as_f64()))
        .filter(|x| *x > 0.0)
        .collect();
    let avg_display = if rating_samples.is_empty() {
        Value::Null
    } else {
        let s: f64 = rating_samples.iter().sum::<f64>() / rating_samples.len() as f64;
        json!(s)
    };
    let rating_count_hint = rating_samples.len();

    let latest_files = active_version
        .as_ref()
        .map(|v| versions_dir.join(v).join("files"));
    let latest_pkg = active_version
        .as_ref()
        .map(|v| versions_dir.join(v).join("package.cpkg"));
    let latest_manifest = latest_files
        .as_ref()
        .and_then(|d| read_manifest_from_dir(d))
        .or_else(|| latest_pkg.as_ref().and_then(|p| read_manifest_from_cpkg(p)));

    let signing = match (&latest_manifest, latest_pkg.as_ref()) {
        (Some(m), Some(p)) => signing_fingerprint(m, Some(p.as_path())),
        (Some(m), None) => signing_fingerprint(m, None),
        _ => json!({}),
    };

    let report_url = format!(
        "https://connector.ai/contact?subject={}",
        urlencoding::encode(&format!("Plugin report: {}", plugin_id))
    );

    Ok(Json(json!({
        "ok": true,
        "plugin_id": plugin_id,
        "lifecycle": life,
        "active_version": active_version,
        "versions": versions,
        "hub_index_hits": hub_rows,
        "hub_install_count_total": hub_install_total,
        "avg_rating": avg_display,
        "rating_count_hint": rating_count_hint,
        "local_install_count": local_install_count(&state, &plugin_id),
        "signing": signing,
        "report_url": report_url,
        "screenshots_note": "Screenshots: see hub_index_hits[].screenshot_paths or package files under screenshots/ when extracted.",
    })))
}
