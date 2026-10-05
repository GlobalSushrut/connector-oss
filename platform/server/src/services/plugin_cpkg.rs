//! Phase 4 — `.cpkg` install (verify, URL sideload), atomic rollout metadata, health rollback, bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::auth;
use crate::services::hub_mirrors::hub_mirror_bases;
use crate::services::plugin_depends;
use crate::services::plugin_lifecycle::{
    load_plugin_lifecycle_state, persist_lifecycle_event, persist_plugin_lifecycle_state,
    PluginLifecycleEvent, PluginLifecycleState,
};
use crate::services::runtime_control;
use crate::state::SharedState;

#[derive(Debug, Deserialize, Clone)]
pub struct CpkgTrustKeyJson {
    pub key_id: String,
    pub pubkey_b64: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HubFetchSpec {
    pub plugin_id: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CpkgInstallBody {
    #[serde(default)]
    pub cpkg_base64: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub hub_fetch: Option<HubFetchSpec>,
    #[serde(default)]
    pub verify_health_sec: Option<u64>,
    #[serde(default)]
    pub require_signature: bool,
    #[serde(default)]
    pub trust_keys: Option<Vec<CpkgTrustKeyJson>>,
}

#[derive(Debug, Deserialize)]
pub struct CpkgBundleExportBody {
    pub packages: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CpkgBundleImportBody {
    pub zip_base64: String,
    #[serde(flatten)]
    pub install: CpkgInstallBody,
}

#[derive(Debug, Serialize, Deserialize)]
struct CpkgRollout {
    active_version: String,
    #[serde(default)]
    previous_version: Option<String>,
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), serde_json::Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

fn verifying_map_from_rows(
    rows: &[CpkgTrustKeyJson],
) -> Result<BTreeMap<String, VerifyingKey>, serde_json::Value> {
    let mut m = BTreeMap::new();
    for row in rows {
        let vk = connector_cpkg::parse_verifying_key_b64(&row.pubkey_b64).map_err(|e| {
            json!({"ok": false, "error": format!("trust key {}: {}", row.key_id, e)})
        })?;
        m.insert(row.key_id.clone(), vk);
    }
    Ok(m)
}

fn parse_trust_key_rows_json(raw: &str) -> Result<Vec<CpkgTrustKeyJson>, serde_json::Value> {
    serde_json::from_str(raw).map_err(|e| {
        json!({"ok": false, "error": format!("platform trust_keys JSON: {e}")})
    })
}

/// Server-owned trust roots (`CONNECTOR_CPKG_TRUST_KEYS_FILE` / `CONNECTOR_CPKG_TRUST_KEYS`).
fn load_platform_trust_key_rows() -> Result<Vec<CpkgTrustKeyJson>, serde_json::Value> {
    if let Ok(p) = std::env::var("CONNECTOR_CPKG_TRUST_KEYS_FILE") {
        let p = p.trim();
        if !p.is_empty() {
            let raw = std::fs::read_to_string(p).map_err(|e| {
                json!({"ok": false, "error": format!("CONNECTOR_CPKG_TRUST_KEYS_FILE {p}: {e}")})
            })?;
            return parse_trust_key_rows_json(&raw);
        }
    }
    if let Ok(raw) = std::env::var("CONNECTOR_CPKG_TRUST_KEYS") {
        if !raw.trim().is_empty() {
            return parse_trust_key_rows_json(&raw);
        }
    }
    Ok(Vec::new())
}

/// Production: platform roots are the only authority. Lab: merge platform + request keys.
fn merge_trust_authority(
    platform: &[CpkgTrustKeyJson],
    request: Option<&[CpkgTrustKeyJson]>,
    production_authority: bool,
) -> Result<Option<BTreeMap<String, VerifyingKey>>, serde_json::Value> {
    if production_authority {
        if platform.is_empty() {
            return Err(json!({
                "ok": false,
                "error": "require_signature requires platform trust roots (CONNECTOR_CPKG_TRUST_KEYS_FILE or CONNECTOR_CPKG_TRUST_KEYS)",
            }));
        }
        return Ok(Some(verifying_map_from_rows(platform)?));
    }
    let mut rows: Vec<CpkgTrustKeyJson> = platform.to_vec();
    if let Some(req) = request {
        for r in req {
            if !rows.iter().any(|p| p.key_id == r.key_id) {
                rows.push(r.clone());
            }
        }
    }
    if rows.is_empty() {
        return Ok(None);
    }
    Ok(Some(verifying_map_from_rows(&rows)?))
}

fn trust_map(
    body: &CpkgInstallBody,
) -> Result<Option<BTreeMap<String, VerifyingKey>>, serde_json::Value> {
    let platform = load_platform_trust_key_rows()?;
    merge_trust_authority(&platform, body.trust_keys.as_deref(), env_require_sig())
}

fn plugin_install_lock(plugin_id: &str) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut g = map.lock().unwrap_or_else(|e| e.into_inner());
    g.entry(plugin_id.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn store_root(state: &SharedState) -> PathBuf {
    Path::new(&state.config.data_dir)
        .join("plugins")
        .join("cpkg_store")
}

pub(crate) fn safe_plugin_id(plugin_id: &str) -> String {
    plugin_id.replace(['/', '\\', ':'], "__")
}

pub(crate) fn cpkg_store_plugin_dir(state: &SharedState, plugin_id: &str) -> PathBuf {
    store_root(state).join(safe_plugin_id(plugin_id))
}

pub(crate) fn cpkg_store_exists(state: &SharedState, plugin_id: &str) -> bool {
    cpkg_store_plugin_dir(state, plugin_id).is_dir()
}

pub(crate) fn list_cpkg_store_plugin_ids(state: &SharedState) -> Vec<String> {
    let root = store_root(state);
    let Ok(rd) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in rd.flatten() {
        if ent.path().is_dir() {
            if let Some(name) = ent.file_name().to_str() {
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// Delete on-disk `.cpkg` store for a plugin (real uninstall). Returns whether a directory existed.
pub fn purge_cpkg_store(state: &SharedState, plugin_id: &str) -> Result<bool, String> {
    let dir = cpkg_store_plugin_dir(state, plugin_id);
    if !dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dir).map_err(|e| format!("purge cpkg_store: {e}"))?;
    Ok(true)
}

fn bump_plugin_marketplace_install(state: &SharedState, plugin_id: &str) {
    const FOLDER: &str = "plugin_marketplace_stats";
    let sid = safe_plugin_id(plugin_id);
    let mut es = state.engine_store.lock().unwrap();
    let cur = es
        .folder_get(FOLDER, &sid)
        .ok()
        .flatten()
        .and_then(|v| v.get("local_install_count").and_then(|x| x.as_u64()))
        .unwrap_or(0);
    let _ = es.folder_put(
        FOLDER,
        &sid,
        &json!({ "local_install_count": cur.saturating_add(1) }),
    );
}

fn env_require_sig() -> bool {
    if matches!(
        std::env::var("CONNECTOR_CPKG_REQUIRE_SIGNATURE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    ) {
        return true;
    }
    if matches!(
        std::env::var("CONNECTOR_CPKG_ALLOW_UNSIGNED")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    ) {
        return false;
    }
    // Production / defense-strict default: require signatures.
    crate::services::runtime_control::defense_strict_enabled()
        || matches!(
            std::env::var("CONNECTOR_ENV")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "production" | "prod" | "staging" | "pilots" | "pilot"
        )
}

const MAX_ZIP_FILES: usize = 4096;
const MAX_UNCOMPRESSED: u64 = 200 * 1024 * 1024;

fn zip_entry_is_unsafe(name: &str) -> bool {
    let n = name.replace('\\', "/");
    if n.is_empty() {
        return true;
    }
    if Path::new(&n).is_absolute() || n.starts_with('/') || n.starts_with("~/") {
        return true;
    }
    for part in n.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == ".." {
            return true;
        }
        if part == "." {
            continue;
        }
        if part.len() >= 2 && part.as_bytes()[1] == b':' {
            return true;
        }
    }
    false
}

fn extract_zip(bytes: &[u8], dest: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let dest_canon = dest.canonicalize().map_err(|e| e.to_string())?;
    let cursor = Cursor::new(bytes);
    let mut arch = ZipArchive::new(cursor).map_err(|e| e.to_string())?;
    if arch.len() > MAX_ZIP_FILES {
        return Err(format!(
            "cpkg_zip_too_many_files: {} > {MAX_ZIP_FILES}",
            arch.len()
        ));
    }
    let mut uncompressed: u64 = 0;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for i in 0..arch.len() {
        let mut file = arch.by_index(i).map_err(|e| e.to_string())?;
        if file.is_symlink() {
            return Err(format!("cpkg_zip_symlink_forbidden: {}", file.name()));
        }
        let name = file.name().to_string();
        if name.is_empty() || name.ends_with('/') || name.ends_with('\\') {
            continue;
        }
        if zip_entry_is_unsafe(&name) {
            return Err(format!("cpkg_zip_path_rejected: {name}"));
        }
        let Some(enclosed) = file.enclosed_name() else {
            return Err(format!("cpkg_zip_path_rejected: {name}"));
        };
        let enclosed = enclosed.to_path_buf();
        let key = enclosed.to_string_lossy().replace('\\', "/");
        if !seen.insert(key) {
            return Err(format!("cpkg_zip_duplicate_path: {name}"));
        }
        uncompressed = uncompressed.saturating_add(file.size());
        if uncompressed > MAX_UNCOMPRESSED {
            return Err("cpkg_zip_too_large".into());
        }
        let out = dest_canon.join(&enclosed);
        if !out.starts_with(&dest_canon) {
            return Err(format!("cpkg_zip_path_escaped: {name}"));
        }
        if let Some(p) = out.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        std::fs::write(&out, &buf).map_err(|e| e.to_string())?;
        if let Ok(canon) = out.canonicalize() {
            if !canon.starts_with(&dest_canon) {
                let _ = std::fs::remove_file(&out);
                return Err(format!("cpkg_zip_path_escaped: {name}"));
            }
        }
    }
    Ok(())
}

fn read_rollout(path: &Path) -> Option<CpkgRollout> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_rollout(path: &Path, r: &CpkgRollout) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(r).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

fn atomic_commit_version_dir(staging: &Path, ver_dir: &Path) -> Result<(), String> {
    if let Some(parent) = ver_dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let prev = ver_dir.with_extension("prev-swap");
    if prev.exists() {
        let _ = std::fs::remove_dir_all(&prev);
    }
    let had_existing = ver_dir.exists();
    if had_existing {
        std::fs::rename(ver_dir, &prev).map_err(|e| e.to_string())?;
    }
    match std::fs::rename(staging, ver_dir) {
        Ok(()) => {
            if had_existing {
                let _ = std::fs::remove_dir_all(&prev);
            }
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(staging);
            if had_existing {
                let _ = std::fs::rename(&prev, ver_dir);
            }
            Err(e.to_string())
        }
    }
}

fn parse_pkg_spec(spec: &str) -> Result<(&str, Option<&str>), String> {
    if let Some((id, ver)) = spec.rsplit_once('@') {
        if id.is_empty() || ver.is_empty() {
            return Err("invalid package spec".into());
        }
        Ok((id, Some(ver)))
    } else {
        Ok((spec, None))
    }
}

fn parse_and_verify_cpkg(
    bytes: &[u8],
    body: &CpkgInstallBody,
) -> Result<connector_cpkg::CpkgBundle, (StatusCode, Json<serde_json::Value>)> {
    let require_sig = body.require_signature || env_require_sig();
    let trust = trust_map(body).map_err(|e| (StatusCode::BAD_REQUEST, Json(e)))?;

    let bundle = match (&trust, require_sig) {
        (_, true) => {
            let Some(ref t) = trust else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "ok": false,
                        "error": "require_signature requires platform trust roots (CONNECTOR_CPKG_TRUST_KEYS_FILE or CONNECTOR_CPKG_TRUST_KEYS)"
                    })),
                ));
            };
            connector_cpkg::read_cpkg_verify_optional(bytes, Some(t)).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok": false, "error": e.to_string()})),
                )
            })?
        }
        (Some(t), false) => {
            connector_cpkg::read_cpkg_verify_optional(bytes, Some(t)).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok": false, "error": e.to_string()})),
                )
            })?
        }
        (None, false) => connector_cpkg::read_cpkg(bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?,
    };

    bundle.manifest.validate().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": e.to_string()})),
        )
    })?;
    Ok(bundle)
}

async fn fetch_hub_cpkg_bytes(
    state: &SharedState,
    plugin_id: &str,
    version: &str,
) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?;
    let mut last = String::new();
    for base in hub_mirror_bases(state) {
        let url = format!(
            "{}/v1/cpkg?plugin_id={}&version={}",
            base.trim_end_matches('/'),
            urlencoding::encode(plugin_id),
            urlencoding::encode(version),
        );
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(b) => return Ok(b.to_vec()),
                Err(e) => last = format!("{base}: {e}"),
            },
            Ok(resp) => last = format!("{base}: HTTP {}", resp.status()),
            Err(e) => last = format!("{base}: {e}"),
        }
    }
    Err((
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "ok": false,
            "error": format!("hub fetch failed (all mirrors): {last}"),
        })),
    ))
}

fn install_source_count(body: &CpkgInstallBody) -> usize {
    body.cpkg_base64.is_some() as usize
        + body.url.is_some() as usize
        + body.hub_fetch.is_some() as usize
}

async fn resolve_install_bytes(
    state: &SharedState,
    body: &CpkgInstallBody,
) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    let n = install_source_count(body);
    if n != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "provide exactly one of cpkg_base64, url, or hub_fetch { plugin_id, version }",
            })),
        ));
    }
    if let Some(b64) = body.cpkg_base64.as_ref() {
        return base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok": false, "error": format!("base64: {}", e)})),
                )
            });
    }
    if let Some(url) = body.url.as_ref() {
        if let Err(code) = crate::substrate::egress_policy::assert_safe_outbound_url(url) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": code})),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "error": e.to_string()})),
                )
            })?;
        let resp = client.get(url).send().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "error": format!("fetch url: {}", e)})),
            )
        })?;
        if !resp.status().is_success() {
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "error": format!("url status {}", resp.status())})),
            ));
        }
        let bytes = resp.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?;
        const MAX_CPKG_FETCH: usize = 50 * 1024 * 1024;
        if bytes.len() > MAX_CPKG_FETCH {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"ok": false, "error": "cpkg_fetch_too_large"})),
            ));
        }
        return Ok(bytes.to_vec());
    }
    if let Some(ref hf) = body.hub_fetch {
        return fetch_hub_cpkg_bytes(state, hf.plugin_id.trim(), hf.version.trim()).await;
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({"ok": false, "error": "no install source"})),
    ))
}

async fn install_cpkg_bytes(
    state: SharedState,
    headers: &HeaderMap,
    bytes: Vec<u8>,
    body: CpkgInstallBody,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }

    let bundle = parse_and_verify_cpkg(&bytes, &body)?;

    if let Err(dep_err) = plugin_depends::evaluate_depends_for_install(&bundle.manifest, &state) {
        return Err((StatusCode::CONFLICT, Json(dep_err)));
    }

    let plugin_id = bundle.manifest.plugin.id.clone();
    let version = bundle.manifest.plugin.version.clone();
    let cold_start_budget_ms = bundle.manifest.runtime.cold_start_budget_ms;
    drop(bundle);
    let sid = safe_plugin_id(&plugin_id);
    let lock = plugin_install_lock(&sid);

    let root = store_root(&state);
    let plugin_dir = root.join(&sid);
    let versions_dir = plugin_dir.join("versions");
    let ver_dir = versions_dir.join(&version);
    let rollout_path = plugin_dir.join("rollout.json");

    let before = crate::services::unified_health::unified_overall_status(&state).await;
    let previous_version = {
        let _install_guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        std::fs::create_dir_all(&versions_dir).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?;

        let staging = versions_dir.join(format!(
            "{version}.staging-{}",
            uuid::Uuid::new_v4().simple()
        ));
        if staging.exists() {
            let _ = std::fs::remove_dir_all(&staging);
        }
        std::fs::create_dir_all(&staging).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?;

        let prev_rollout = read_rollout(&rollout_path);
        let previous_version = prev_rollout.as_ref().map(|r| r.active_version.clone());
        let old = load_plugin_lifecycle_state(&state, &plugin_id);

        let stage_err = |e: String| {
            let _ = std::fs::remove_dir_all(&staging);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": e})),
            )
        };

        std::fs::write(staging.join("package.cpkg"), &bytes).map_err(|e| stage_err(e.to_string()))?;
        let files_dir = staging.join("files");
        extract_zip(&bytes, &files_dir).map_err(stage_err)?;
        if let Err(e) = crate::services::cpkg_gloo_burnin::verify_staged_gloo_package(&files_dir) {
            return Err(stage_err(e));
        }
        atomic_commit_version_dir(&staging, &ver_dir).map_err(stage_err)?;
        write_rollout(
            &rollout_path,
            &CpkgRollout {
                active_version: version.clone(),
                previous_version: previous_version.clone(),
            },
        )
        .map_err(stage_err)?;

        let row = PluginLifecycleState {
            plugin_id: plugin_id.clone(),
            installed: true,
            enabled: true,
            version: version.clone(),
            revision: old.revision.saturating_add(1),
            last_action: "cpkg_install".into(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        persist_plugin_lifecycle_state(&state, &row);
        persist_lifecycle_event(
            &state,
            &PluginLifecycleEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                plugin_id: plugin_id.clone(),
                action: "cpkg_install".into(),
                from_installed: old.installed,
                from_enabled: old.enabled,
                to_installed: true,
                to_enabled: true,
                from_version: old.version.clone(),
                to_version: version.clone(),
                at: chrono::Utc::now().to_rfc3339(),
            },
        );
        previous_version
    };

    let mut response = json!({
        "ok": true,
        "plugin_id": plugin_id,
        "version": version,
        "extracted_to": ver_dir.to_string_lossy(),
        "rollout": {
            "previous_version": previous_version,
            "health_rollback": false
        }
    });

    let mut health_worsened = false;
    if let Some(sec) = body.verify_health_sec.filter(|s| *s > 0) {
        tokio::time::sleep(std::time::Duration::from_secs(sec.min(300))).await;
        let after = crate::services::unified_health::unified_overall_status(&state).await;
        health_worsened = before == "ok" && (after == "degraded" || after == "critical");
        if health_worsened {
            if let Some(ref pv) = previous_version {
                let _rb = lock.lock().unwrap_or_else(|e| e.into_inner());
                let _ = write_rollout(
                    &rollout_path,
                    &CpkgRollout {
                        active_version: pv.clone(),
                        previous_version: None,
                    },
                );
                let mut back = load_plugin_lifecycle_state(&state, &plugin_id);
                back.version = pv.clone();
                back.last_action = "cpkg_rollback_health".into();
                back.updated_at = chrono::Utc::now().to_rfc3339();
                persist_plugin_lifecycle_state(&state, &back);
                response["rollout"]["health_rollback"] = json!(true);
                response["rollout"]["rolled_back_to"] = json!(pv);
            } else {
                response["rollout"]["health_rollback_wanted"] = json!(true);
                response["rollout"]["note"] = json!("no previous_version to restore");
            }
        }
    }

    let rolled = response["rollout"]["health_rollback"].as_bool() == Some(true);
    if !rolled {
        bump_plugin_marketplace_install(&state, &plugin_id);
    }

    let burn_in = if !rolled {
        let files_dir = ver_dir.join("files");
        crate::services::cpkg_gloo_burnin::burn_in_installed_cpkg(
            &state,
            &plugin_id,
            &version,
            &files_dir,
        )
        .await
    } else {
        json!({"ok": false, "skipped": true, "reason": "install rolled back"})
    };
    response["burn_in"] = burn_in;

    // Phase 5.4 / 5.10 — tie tier cold-start + crash hints to real install outcomes.
    if rolled || health_worsened {
        state
            .plugin_crash_recovery
            .record_failure(state.as_ref(), &plugin_id);
    } else {
        state
            .plugin_crash_recovery
            .clear(state.as_ref(), &plugin_id);
        state
            .plugin_tier_scheduler
            .admit_cold_start(&plugin_id, cold_start_budget_ms)
            .await;
    }

    Ok(Json(response))
}

pub async fn post_cpkg_preflight(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CpkgInstallBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let require_sig = body.require_signature || env_require_sig();
    if require_sig && body.trust_keys.as_ref().map_or(true, |v| v.is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "require_signature requires non-empty trust_keys"})),
        ));
    }
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let bytes = resolve_install_bytes(&state, &body).await?;
    let bundle = parse_and_verify_cpkg(&bytes, &body)?;
    if let Err(dep_err) = plugin_depends::evaluate_depends_for_install(&bundle.manifest, &state) {
        return Err((StatusCode::CONFLICT, Json(dep_err)));
    }
    let caps = bundle.manifest.capabilities.required.clone();
    Ok(Json(json!({
        "ok": true,
        "preflight": "ok",
        "plugin_id": bundle.manifest.plugin.id,
        "version": bundle.manifest.plugin.version,
        "capabilities": caps,
        "depends": bundle.manifest.depends,
    })))
}

pub async fn post_cpkg_install(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CpkgInstallBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let require_sig = body.require_signature || env_require_sig();
    if require_sig && body.trust_keys.as_ref().map_or(true, |v| v.is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "require_signature requires non-empty trust_keys"})),
        ));
    }

    let bytes = resolve_install_bytes(&state, &body).await?;
    install_cpkg_bytes(state, &headers, bytes, body).await
}

pub async fn post_cpkg_bundle_export(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CpkgBundleExportBody>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let root = store_root(&state);
    let mut zip_buf = Vec::new();
    {
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let mut zip = ZipWriter::new(Cursor::new(&mut zip_buf));
        for spec in &body.packages {
            let (pid, ver_opt) = parse_pkg_spec(spec).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok": false, "error": e})),
                )
            })?;
            let sid = safe_plugin_id(pid);
            let rollout = read_rollout(&root.join(&sid).join("rollout.json")).ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"ok": false, "error": format!("no rollout for {}", pid)})),
                )
            })?;
            let ver = ver_opt
                .map(|s| s.to_string())
                .unwrap_or_else(|| rollout.active_version.clone());
            let pkg_path = root
                .join(&sid)
                .join("versions")
                .join(&ver)
                .join("package.cpkg");
            let data = std::fs::read(&pkg_path).map_err(|e| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"ok": false, "error": format!("{}: {}", pkg_path.display(), e)})),
                )
            })?;
            let arc_name = format!("{}__{}.cpkg", sid, ver);
            zip.start_file(&arc_name, opts).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "error": e.to_string()})),
                )
            })?;
            zip.write_all(&data).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "error": e.to_string()})),
                )
            })?;
        }
        zip.finish().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?;
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"connector-cpkg-bundle.zip\"",
        )
        .body(Body::from(zip_buf))
        .unwrap())
}

pub async fn post_cpkg_bundle_import(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CpkgBundleImportBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let zip_bytes = base64::engine::general_purpose::STANDARD
        .decode(body.zip_base64.trim())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": format!("zip base64: {}", e)})),
            )
        })?;

    let cursor = Cursor::new(zip_bytes);
    let mut arch = ZipArchive::new(cursor).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": e.to_string()})),
        )
    })?;

    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for i in 0..arch.len() {
        let mut file = arch.by_index(i).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?;
        let name = file.name().to_string();
        if !name.ends_with(".cpkg") || name.ends_with('/') {
            continue;
        }
        let mut inner = Vec::new();
        file.read_to_end(&mut inner).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
        })?;
        payloads.push(inner);
    }

    let mut results = Vec::new();
    for inner in payloads {
        let st = state.clone();
        let hdr = headers.clone();
        let mut ib = body.install.clone();
        ib.cpkg_base64 = None;
        ib.url = None;
        ib.hub_fetch = None;
        let Json(j) = install_cpkg_bytes(st, &hdr, inner, ib).await?;
        results.push(j);
    }

    Ok(Json(json!({"ok": true, "installed": results})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;

    fn zip_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for (name, data) in entries {
                zip.start_file(*name, opts).unwrap();
                zip.write_all(data).unwrap();
            }
            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn zip_slip_parent_and_absolute_rejected() {
        let tmp = std::env::temp_dir().join(format!("cpkg-zip-{}", uuid::Uuid::new_v4().simple()));
        let _ = std::fs::create_dir_all(&tmp);
        let bytes = zip_with_entries(&[("../evil.txt", b"nope"), ("ok.txt", b"yes")]);
        let err = extract_zip(&bytes, &tmp).unwrap_err();
        assert!(
            err.contains("cpkg_zip_path_rejected") || err.contains("evil"),
            "unexpected err: {err}"
        );
        assert!(!tmp.join("ok.txt").exists() || !tmp.join("evil.txt").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn zip_slip_absolute_rejected() {
        let tmp = std::env::temp_dir().join(format!("cpkg-abs-{}", uuid::Uuid::new_v4().simple()));
        let _ = std::fs::create_dir_all(&tmp);
        let bytes = zip_with_entries(&[("/tmp/evil-cpkg.txt", b"nope")]);
        let err = extract_zip(&bytes, &tmp).unwrap_err();
        assert!(err.contains("cpkg_zip_path_rejected"), "unexpected err: {err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn zip_safe_relative_extracts() {
        let tmp = std::env::temp_dir().join(format!("cpkg-ok-{}", uuid::Uuid::new_v4().simple()));
        let _ = std::fs::create_dir_all(&tmp);
        let bytes = zip_with_entries(&[("nested/a.txt", b"hello")]);
        extract_zip(&bytes, &tmp).unwrap();
        assert_eq!(std::fs::read(tmp.join("nested/a.txt")).unwrap(), b"hello");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn valid_trust_row(key_id: &str, seed: u8) -> CpkgTrustKeyJson {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().as_bytes());
        CpkgTrustKeyJson {
            key_id: key_id.to_string(),
            pubkey_b64: b64,
        }
    }

    #[test]
    fn production_trust_ignores_caller_keys() {
        let platform = vec![valid_trust_row("root", 1)];
        let request = vec![valid_trust_row("attacker", 2)];
        let merged = merge_trust_authority(&platform, Some(&request), true)
            .unwrap()
            .unwrap();
        assert!(merged.contains_key("root"));
        assert!(!merged.contains_key("attacker"));
    }

    #[test]
    fn production_trust_requires_platform_roots() {
        let request = vec![CpkgTrustKeyJson {
            key_id: "attacker".into(),
            pubkey_b64: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".into(),
        }];
        let err = merge_trust_authority(&[], Some(&request), true).unwrap_err();
        assert!(err
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("platform trust roots"));
    }
}
