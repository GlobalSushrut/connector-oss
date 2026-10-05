//! Tenant-filtered target / surface / channel catalog.
//!
//! Builds on `channel_ref_v1` / `surface_ref_v1` — does not invent a parallel identity.
//! Descriptors are discovery metadata only (never mint grants). Unknown surfaces stay valid.

use connector_engine::engine_store::EngineStore;
use connector_native_contract::{
    ChannelRef, SurfaceRef, TargetDescriptor, TargetRef, TARGET_DESCRIPTOR_SCHEMA,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};
use crate::substrate::channel_surface::{self, CHANNEL_FOLDER, SURFACE_FOLDER};

pub const CATALOG_META_FOLDER: &str = "target_catalog_meta_v1";
pub const CATALOG_INDEX_FOLDER: &str = "target_catalog_index_v1";
pub const CATALOG_DESC_FOLDER: &str = "target_catalog_desc_v1";
pub const CHANNEL_INDEX_FOLDER: &str = "channel_catalog_index_v1";
pub const SURFACE_TENANT_FOLDER: &str = "surface_tenant_map_v1";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn normalize_tenant(tenant_id: Option<&str>) -> String {
    let t = tenant_id.unwrap_or("default").trim();
    if t.is_empty() {
        "default".into()
    } else {
        t.into()
    }
}

/// Read tenant from observation hints (`raw_hints.tenant_id`), defaulting to `"default"`.
pub fn tenant_from_hints(hints: &Value) -> String {
    hints
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("default")
        .into()
}

fn meta_key(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
}

fn surface_index_key(tenant_id: &str, surface_uid: &str) -> String {
    format!("{tenant_id}:surf:{surface_uid}")
}

fn channel_index_key(tenant_id: &str, channel_uid: &str) -> String {
    format!("{tenant_id}:ch:{channel_uid}")
}

fn channel_body_key(tenant_id: &str, channel_uid: &str) -> String {
    format!("{tenant_id}:body:{channel_uid}")
}

fn desc_key(tenant_id: &str, surface_uid: &str) -> String {
    format!("{tenant_id}:{surface_uid}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogMeta {
    pub tenant_id: String,
    pub revision: u64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogIndexEntry {
    pub uid: String,
    pub kind: String,
    pub tenant_id: String,
    pub catalog_revision: u64,
    pub updated_at_ms: i64,
}

fn get_json<T: for<'de> Deserialize<'de>>(
    es: &dyn EngineStore,
    folder: &str,
    key: &str,
) -> Option<T> {
    channel_surface::get_json(es, folder, key)
}

fn put_json(
    es: &mut dyn EngineStore,
    folder: &str,
    key: &str,
    value: &impl Serialize,
) -> Result<(), String> {
    channel_surface::put_json(es, folder, key, value)
}

pub fn catalog_revision_store(es: &dyn EngineStore, tenant_id: &str) -> u64 {
    get_json::<CatalogMeta>(es, CATALOG_META_FOLDER, &meta_key(tenant_id))
        .map(|m| m.revision)
        .unwrap_or(0)
}

fn bump_catalog_revision(es: &mut dyn EngineStore, tenant_id: &str) -> Result<u64, String> {
    let tenant = normalize_tenant(Some(tenant_id));
    let mut meta = get_json::<CatalogMeta>(es, CATALOG_META_FOLDER, &meta_key(&tenant)).unwrap_or(
        CatalogMeta {
            tenant_id: tenant.clone(),
            revision: 0,
            updated_at_ms: 0,
        },
    );
    meta.revision = meta.revision.saturating_add(1);
    meta.updated_at_ms = now_ms();
    put_json(es, CATALOG_META_FOLDER, &meta_key(&tenant), &meta)?;
    Ok(meta.revision)
}

/// Index a surface into the tenant catalog (called from observe/enrich).
pub fn index_surface_store(
    es: &mut dyn EngineStore,
    surface: &SurfaceRef,
    tenant_id: Option<&str>,
    target: Option<TargetRef>,
) -> Result<TargetDescriptor, String> {
    let tenant = normalize_tenant(tenant_id);
    let rev = bump_catalog_revision(es, &tenant)?;
    let mut desc = TargetDescriptor::from_surface(surface, &tenant, rev, target);
    if let Some(prev) =
        get_json::<TargetDescriptor>(es, CATALOG_DESC_FOLDER, &desc_key(&tenant, &surface.surface_uid))
    {
        desc.readiness = prev.readiness;
        desc.last_probe_at_ms = prev.last_probe_at_ms;
        desc.supervised_workload_uid = prev.supervised_workload_uid;
        desc.workload_lifecycle = prev.workload_lifecycle;
    }
    desc.updated_at_ms = now_ms();
    desc.schema = TARGET_DESCRIPTOR_SCHEMA.into();

    let idx = CatalogIndexEntry {
        uid: surface.surface_uid.clone(),
        kind: "surface".into(),
        tenant_id: tenant.clone(),
        catalog_revision: rev,
        updated_at_ms: desc.updated_at_ms,
    };
    put_json(
        es,
        CATALOG_INDEX_FOLDER,
        &surface_index_key(&tenant, &surface.surface_uid),
        &idx,
    )?;
    put_json(
        es,
        CATALOG_DESC_FOLDER,
        &desc_key(&tenant, &surface.surface_uid),
        &desc,
    )?;
    put_json(
        es,
        SURFACE_TENANT_FOLDER,
        &surface.surface_uid,
        &json!({ "tenant_id": tenant }),
    )?;
    Ok(desc)
}

/// Look up the tenant that first indexed this surface (for enrich re-index).
pub fn tenant_for_surface_store(es: &dyn EngineStore, surface_uid: &str) -> Option<String> {
    get_json::<Value>(es, SURFACE_TENANT_FOLDER, surface_uid)
        .and_then(|v| v.get("tenant_id")?.as_str().map(str::to_string))
}

pub fn index_channel_store(
    es: &mut dyn EngineStore,
    channel: &ChannelRef,
    tenant_id: Option<&str>,
) -> Result<u64, String> {
    let tenant = normalize_tenant(tenant_id);
    let rev = bump_catalog_revision(es, &tenant)?;
    let idx = CatalogIndexEntry {
        uid: channel.channel_uid.clone(),
        kind: "channel".into(),
        tenant_id: tenant.clone(),
        catalog_revision: rev,
        updated_at_ms: now_ms(),
    };
    put_json(
        es,
        CHANNEL_INDEX_FOLDER,
        &channel_index_key(&tenant, &channel.channel_uid),
        &idx,
    )?;
    put_json(
        es,
        CHANNEL_INDEX_FOLDER,
        &channel_body_key(&tenant, &channel.channel_uid),
        channel,
    )?;
    Ok(rev)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceListResult {
    pub tenant_id: String,
    pub catalog_revision: u64,
    pub surfaces: Vec<TargetDescriptor>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelListResult {
    pub tenant_id: String,
    pub catalog_revision: u64,
    pub channels: Vec<ChannelRef>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogWatchResult {
    pub tenant_id: String,
    pub since_revision: u64,
    pub catalog_revision: u64,
    pub changed_surfaces: Vec<TargetDescriptor>,
    pub changed_channels: Vec<CatalogIndexEntry>,
    pub has_changes: bool,
}

pub fn list_surfaces_store(
    es: &dyn EngineStore,
    tenant_id: Option<&str>,
    min_revision: Option<u64>,
) -> Result<SurfaceListResult, String> {
    let tenant = normalize_tenant(tenant_id);
    let catalog_revision = catalog_revision_store(es, &tenant);
    let prefix = format!("{tenant}:surf:");
    let keys = es
        .folder_keys(CATALOG_INDEX_FOLDER, Some(&prefix))
        .map_err(|e| e.to_string())?;
    let min_rev = min_revision.unwrap_or(0);
    let mut surfaces = Vec::new();
    for key in keys {
        let Some(idx) = get_json::<CatalogIndexEntry>(es, CATALOG_INDEX_FOLDER, &key) else {
            continue;
        };
        if idx.catalog_revision < min_rev {
            continue;
        }
        if let Some(desc) =
            get_json::<TargetDescriptor>(es, CATALOG_DESC_FOLDER, &desc_key(&tenant, &idx.uid))
        {
            surfaces.push(desc);
        } else if let Some(surface) = get_json::<SurfaceRef>(es, SURFACE_FOLDER, &idx.uid) {
            surfaces.push(TargetDescriptor::from_surface(
                &surface,
                &tenant,
                idx.catalog_revision,
                None,
            ));
        }
    }
    surfaces.sort_by(|a, b| a.surface_uid.cmp(&b.surface_uid));
    Ok(SurfaceListResult {
        count: surfaces.len(),
        surfaces,
        tenant_id: tenant,
        catalog_revision,
    })
}

pub fn list_channels_store(
    es: &dyn EngineStore,
    tenant_id: Option<&str>,
    min_revision: Option<u64>,
) -> Result<ChannelListResult, String> {
    let tenant = normalize_tenant(tenant_id);
    let catalog_revision = catalog_revision_store(es, &tenant);
    let prefix = format!("{tenant}:ch:");
    let keys = es
        .folder_keys(CHANNEL_INDEX_FOLDER, Some(&prefix))
        .map_err(|e| e.to_string())?;
    let min_rev = min_revision.unwrap_or(0);
    let mut channels = Vec::new();
    for key in keys {
        if key.contains(":body:") {
            continue;
        }
        let Some(idx) = get_json::<CatalogIndexEntry>(es, CHANNEL_INDEX_FOLDER, &key) else {
            continue;
        };
        if idx.catalog_revision < min_rev {
            continue;
        }
        if let Some(ch) = get_json::<ChannelRef>(
            es,
            CHANNEL_INDEX_FOLDER,
            &channel_body_key(&tenant, &idx.uid),
        )
        .or_else(|| get_json::<ChannelRef>(es, CHANNEL_FOLDER, &idx.uid))
        {
            channels.push(ch);
        }
    }
    channels.sort_by(|a, b| a.channel_uid.cmp(&b.channel_uid));
    Ok(ChannelListResult {
        count: channels.len(),
        channels,
        tenant_id: tenant,
        catalog_revision,
    })
}

/// Poll-style watch: entries with `catalog_revision > since_revision`.
pub fn watch_catalog_store(
    es: &dyn EngineStore,
    tenant_id: Option<&str>,
    since_revision: u64,
) -> Result<CatalogWatchResult, String> {
    let tenant = normalize_tenant(tenant_id);
    let catalog_revision = catalog_revision_store(es, &tenant);
    let changed_surfaces =
        list_surfaces_store(es, Some(&tenant), Some(since_revision.saturating_add(1)))?.surfaces;

    let prefix = format!("{tenant}:ch:");
    let keys = es
        .folder_keys(CHANNEL_INDEX_FOLDER, Some(&prefix))
        .map_err(|e| e.to_string())?;
    let mut changed_channels = Vec::new();
    for key in keys {
        if key.contains(":body:") {
            continue;
        }
        if let Some(idx) = get_json::<CatalogIndexEntry>(es, CHANNEL_INDEX_FOLDER, &key) {
            if idx.catalog_revision > since_revision {
                changed_channels.push(idx);
            }
        }
    }

    let has_changes = catalog_revision > since_revision
        || !changed_surfaces.is_empty()
        || !changed_channels.is_empty();

    Ok(CatalogWatchResult {
        tenant_id: tenant,
        since_revision,
        catalog_revision,
        changed_surfaces,
        changed_channels,
        has_changes,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Optional supervised workload binding (advisory — not a spawn).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervised_workload_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_lifecycle: Option<String>,
}

/// Lifecycle probe: updates readiness from surface presence + optional workload hint.
/// Does not claim TransportEnforced confinement or spawn a runtime.
pub fn probe_surface_store(
    es: &mut dyn EngineStore,
    surface_uid: &str,
    req: &ProbeRequest,
) -> Result<TargetDescriptor, String> {
    let tenant = normalize_tenant(req.tenant_id.as_deref());
    let surface: SurfaceRef = get_json(es, SURFACE_FOLDER, surface_uid)
        .ok_or_else(|| "surface_not_found".to_string())?;

    let mut desc = get_json::<TargetDescriptor>(es, CATALOG_DESC_FOLDER, &desc_key(&tenant, surface_uid))
        .unwrap_or_else(|| {
            TargetDescriptor::from_surface(&surface, &tenant, catalog_revision_store(es, &tenant), None)
        });

    let readiness = if surface.locators.is_empty() {
        "unready"
    } else if matches!(
        req.workload_lifecycle.as_deref(),
        Some("degraded") | Some("draining") | Some("stopped")
    ) {
        "degraded"
    } else if req.supervised_workload_uid.is_some()
        || !matches!(
            surface.semantic_state,
            connector_native_contract::SemanticResolutionState::Unresolved
        )
    {
        // Supervised binding or any resolved semantic state → ready for catalog purposes.
        // Unresolved+locators without supervision stays "unknown" (honest).
        "ready"
    } else {
        "unknown"
    };

    desc.readiness = readiness.into();
    desc.last_probe_at_ms = Some(now_ms());
    desc.surface_revision = surface.revision;
    desc.confidence = surface.confidence;
    desc.semantic_state = surface.semantic_state;
    desc.locators = surface.locators.clone();
    if let Some(ref wid) = req.supervised_workload_uid {
        desc.supervised_workload_uid = Some(wid.clone());
    }
    if let Some(ref lc) = req.workload_lifecycle {
        desc.workload_lifecycle = Some(lc.clone());
    }
    desc.updated_at_ms = now_ms();

    let rev = bump_catalog_revision(es, &tenant)?;
    desc.catalog_revision = rev;
    put_json(
        es,
        CATALOG_DESC_FOLDER,
        &desc_key(&tenant, surface_uid),
        &desc,
    )?;
    put_json(
        es,
        CATALOG_INDEX_FOLDER,
        &surface_index_key(&tenant, surface_uid),
        &CatalogIndexEntry {
            uid: surface_uid.into(),
            kind: "surface".into(),
            tenant_id: tenant,
            catalog_revision: rev,
            updated_at_ms: desc.updated_at_ms,
        },
    )?;
    Ok(desc)
}

pub fn list_surfaces(
    state: &PlatformState,
    tenant_id: Option<&str>,
    min_revision: Option<u64>,
) -> Result<SurfaceListResult, String> {
    let es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    list_surfaces_store(es.as_ref(), tenant_id, min_revision)
}

pub fn list_channels(
    state: &PlatformState,
    tenant_id: Option<&str>,
    min_revision: Option<u64>,
) -> Result<ChannelListResult, String> {
    let es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    list_channels_store(es.as_ref(), tenant_id, min_revision)
}

pub fn watch_catalog(
    state: &PlatformState,
    tenant_id: Option<&str>,
    since_revision: u64,
) -> Result<CatalogWatchResult, String> {
    let es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    watch_catalog_store(es.as_ref(), tenant_id, since_revision)
}

pub fn probe_surface(
    state: &PlatformState,
    surface_uid: &str,
    req: ProbeRequest,
) -> Result<TargetDescriptor, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    probe_surface_store(es.as_mut(), surface_uid, &req)
}

// ── HTTP ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CatalogQuery {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub since_revision: Option<u64>,
    #[serde(default)]
    pub min_revision: Option<u64>,
}

pub async fn get_surfaces(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<CatalogQuery>,
) -> axum::Json<Value> {
    match list_surfaces(state.as_ref(), q.tenant_id.as_deref(), q.min_revision) {
        Ok(res) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "tenant_id": res.tenant_id,
            "catalog_revision": res.catalog_revision,
            "count": res.count,
            "surfaces": res.surfaces,
            "honesty": "Descriptors are discovery metadata; listing does not grant authority. Unknown surfaces remain valid.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn get_channels(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<CatalogQuery>,
) -> axum::Json<Value> {
    match list_channels(state.as_ref(), q.tenant_id.as_deref(), q.min_revision) {
        Ok(res) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "tenant_id": res.tenant_id,
            "catalog_revision": res.catalog_revision,
            "count": res.count,
            "channels": res.channels,
            "honesty": "Channel catalog is tenant-filtered observation metadata, not admission.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn get_catalog_watch(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<CatalogQuery>,
) -> axum::Json<Value> {
    let since = q.since_revision.unwrap_or(0);
    match watch_catalog(state.as_ref(), q.tenant_id.as_deref(), since) {
        Ok(res) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "tenant_id": res.tenant_id,
            "since_revision": res.since_revision,
            "catalog_revision": res.catalog_revision,
            "has_changes": res.has_changes,
            "changed_surfaces": res.changed_surfaces,
            "changed_channels": res.changed_channels,
            "honesty": "Poll watch — not a push subscription; clients advance since_revision from catalog_revision.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn post_probe_surface(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<ProbeRequest>,
) -> axum::Json<Value> {
    match probe_surface(state.as_ref(), &id, req) {
        Ok(desc) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "descriptor": desc,
            "honesty": "Probe updates readiness/supervision hints only; it does not spawn or claim TransportEnforced confinement.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;
    use connector_native_contract::{
        ChannelDirection, ChannelObservation, SemanticConfidence, TransportObservation,
    };

    fn observe_pair(es: &mut InMemoryEngineStore, dest: &str, tenant: &str) -> (ChannelRef, SurfaceRef) {
        let obs = ChannelObservation {
            origin_intelligence: "intel_1".into(),
            origin_workload: "wl_1".into(),
            direction: ChannelDirection::Outbound,
            transport: TransportObservation {
                transport: "tcp".into(),
                destination: Some(dest.into()),
                ..Default::default()
            },
            observed_at_ms: 1,
            raw_hints: json!({ "tenant_id": tenant }),
        };
        let (ch, surf) = channel_surface::observe_channel_store(es, obs).unwrap();
        let _ = index_surface_store(es, &surf, Some(tenant), None).unwrap();
        let _ = index_channel_store(es, &ch, Some(tenant)).unwrap();
        (ch, surf)
    }

    #[test]
    fn list_is_tenant_isolated() {
        let mut es = InMemoryEngineStore::new();
        let (_c1, s1) = observe_pair(&mut es, "https://a.example", "t1");
        let (_c2, s2) = observe_pair(&mut es, "https://b.example", "t2");

        let t1 = list_surfaces_store(&es, Some("t1"), None).unwrap();
        assert_eq!(t1.count, 1);
        assert_eq!(t1.surfaces[0].surface_uid, s1.surface_uid);
        assert_eq!(t1.tenant_id, "t1");

        let t2 = list_surfaces_store(&es, Some("t2"), None).unwrap();
        assert_eq!(t2.count, 1);
        assert_eq!(t2.surfaces[0].surface_uid, s2.surface_uid);
        assert!(!t2.surfaces.iter().any(|d| d.surface_uid == s1.surface_uid));
    }

    #[test]
    fn watch_sees_resolve_upgrade() {
        let mut es = InMemoryEngineStore::new();
        let (_ch, surf) = observe_pair(&mut es, "https://watch.example", "tw");
        let before = catalog_revision_store(&es, "tw");

        let enriched = channel_surface::enrich_surface_store(
            &mut es,
            &surf.surface_uid,
            SemanticConfidence::AdapterVerified,
            connector_native_contract::SemanticProvenance::SignedAdapter {
                adapter_ref: "adapter:test".into(),
            },
            None,
        )
        .unwrap();
        let _ = index_surface_store(&mut es, &enriched, Some("tw"), None).unwrap();

        let watch = watch_catalog_store(&es, Some("tw"), before).unwrap();
        assert!(watch.has_changes);
        assert!(watch.catalog_revision > before);
        assert!(watch
            .changed_surfaces
            .iter()
            .any(|d| d.surface_uid == surf.surface_uid
                && d.confidence == SemanticConfidence::AdapterVerified));
    }

    #[test]
    fn probe_sets_readiness_without_claiming_enforcement() {
        let mut es = InMemoryEngineStore::new();
        let (_ch, surf) = observe_pair(&mut es, "https://probe.example", "tp");
        let desc = probe_surface_store(
            &mut es,
            &surf.surface_uid,
            &ProbeRequest {
                tenant_id: Some("tp".into()),
                supervised_workload_uid: Some("wl_probe".into()),
                workload_lifecycle: Some("active".into()),
            },
        )
        .unwrap();
        assert_eq!(desc.readiness, "ready");
        assert_eq!(desc.supervised_workload_uid.as_deref(), Some("wl_probe"));
        assert_eq!(desc.workload_lifecycle.as_deref(), Some("active"));
    }

    #[test]
    fn unknown_surface_stays_listable() {
        let mut es = InMemoryEngineStore::new();
        let (_ch, surf) = observe_pair(&mut es, "unknown://opaque", "tu");
        let list = list_surfaces_store(&es, Some("tu"), None).unwrap();
        assert_eq!(list.count, 1);
        assert_eq!(list.surfaces[0].confidence, SemanticConfidence::TransportOnly);
        assert_eq!(list.surfaces[0].surface_uid, surf.surface_uid);
    }
}
