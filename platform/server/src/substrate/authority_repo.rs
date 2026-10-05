//! Tenant authority repository — dual-writes GrantRef beside WorldGrantV1.
//!
//! On mint: ensure AuthorityRoot → bump revision → write GrantRef → write legacy WorldGrant.
//! On revoke: write tombstone → bump revision → mark GrantRef revoked → delete WorldGrant.
//! Legacy WorldGrant rows remain readable; they must not mint delegated children.

use connector_engine::engine_store::EngineStore;
use connector_trust::{
    attenuates_ok, attenuation_digest, AuthorityRevisionRecord, AuthorityRoot, GrantRef,
    RevocationTombstone, GRANT_REF_SCHEMA, REVISION_SCHEMA, TOMBSTONE_SCHEMA,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::kernel::world_gateway::{self, WorldGrantV1, GRANT_FOLDER};
use crate::state::PlatformState;

pub const ROOT_FOLDER: &str = "authority_roots_v1";
pub const GRANT_REF_FOLDER: &str = "authority_grants_v1";
pub const TOMBSTONE_FOLDER: &str = "authority_tombstones_v1";
pub const REVISION_LOG_FOLDER: &str = "authority_revision_log_v1";

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

fn root_key(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
}

fn grant_ref_key(grant_id: &str) -> String {
    grant_id.to_string()
}

fn principal_index_key(tenant_id: &str, principal_id: &str, resource: &str) -> String {
    format!("idx:{tenant_id}:{principal_id}::{resource}")
}

fn revision_log_key(tenant_id: &str, revision: u64) -> String {
    format!("{tenant_id}:{revision:020}")
}

fn put_json(es: &mut dyn EngineStore, folder: &str, key: &str, v: &impl serde::Serialize) -> Result<(), String> {
    let val = serde_json::to_value(v).map_err(|e| e.to_string())?;
    es.folder_put(folder, key, &val).map_err(|e| e.to_string())
}

fn get_json<T: serde::de::DeserializeOwned>(
    es: &dyn EngineStore,
    folder: &str,
    key: &str,
) -> Result<Option<T>, String> {
    match es.folder_get(folder, key).map_err(|e| e.to_string())? {
        Some(v) => Ok(Some(serde_json::from_value(v).map_err(|e| e.to_string())?)),
        None => Ok(None),
    }
}

/// Ensure a tenant authority root exists (revision starts at 0).
pub fn ensure_root_store(
    es: &mut dyn EngineStore,
    tenant_id: &str,
    issuer: &str,
) -> Result<AuthorityRoot, String> {
    let tenant = normalize_tenant(Some(tenant_id));
    let key = root_key(&tenant);
    if let Some(existing) = get_json::<AuthorityRoot>(es, ROOT_FOLDER, &key)? {
        return Ok(existing);
    }
    let root = AuthorityRoot::new(&tenant, issuer, now_ms());
    put_json(es, ROOT_FOLDER, &key, &root)?;
    let rec = AuthorityRevisionRecord {
        schema: REVISION_SCHEMA.into(),
        tenant_id: tenant.clone(),
        revision: 0,
        event: "root_create".into(),
        grant_id: None,
        at_ms: root.created_at_ms,
    };
    put_json(es, REVISION_LOG_FOLDER, &revision_log_key(&tenant, 0), &rec)?;
    Ok(root)
}

fn bump_revision_store(
    es: &mut dyn EngineStore,
    tenant_id: &str,
    event: &str,
    grant_id: Option<String>,
) -> Result<u64, String> {
    let tenant = normalize_tenant(Some(tenant_id));
    let mut root = ensure_root_store(es, &tenant, "kernel")?;
    root.current_revision = root.current_revision.saturating_add(1);
    let rev = root.current_revision;
    put_json(es, ROOT_FOLDER, &root_key(&tenant), &root)?;
    let rec = AuthorityRevisionRecord {
        schema: REVISION_SCHEMA.into(),
        tenant_id: tenant.clone(),
        revision: rev,
        event: event.into(),
        grant_id,
        at_ms: now_ms(),
    };
    put_json(es, REVISION_LOG_FOLDER, &revision_log_key(&tenant, rev), &rec)?;
    Ok(rev)
}

/// Current tenant authority revision (0 if root missing — will be created on mint).
pub fn current_revision_store(es: &dyn EngineStore, tenant_id: &str) -> u64 {
    let tenant = normalize_tenant(Some(tenant_id));
    get_json::<AuthorityRoot>(es, ROOT_FOLDER, &root_key(&tenant))
        .ok()
        .flatten()
        .map(|r| r.current_revision)
        .unwrap_or(0)
}

pub fn current_revision(state: &PlatformState, tenant_id: Option<&str>) -> u64 {
    let tenant = normalize_tenant(tenant_id);
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    current_revision_store(es.as_ref(), &tenant)
}

/// Fail closed when caller presents a stale or unknown revision.
pub fn require_revision_store(
    es: &dyn EngineStore,
    tenant_id: &str,
    expected: u64,
) -> Result<u64, String> {
    let current = current_revision_store(es, tenant_id);
    if expected == 0 {
        return Err("authority_revision_required".into());
    }
    if expected != current {
        return Err(format!(
            "authority_revision_stale:expected={expected},current={current}"
        ));
    }
    Ok(current)
}

/// Mint GrantRef + dual-write legacy WorldGrant. Returns (grant_ref, revision).
pub fn mint_world_grant_store(
    es: &mut dyn EngineStore,
    grant: &WorldGrantV1,
    tenant_id: Option<&str>,
    parent_grant_id: Option<&str>,
) -> Result<(GrantRef, u64), String> {
    if grant.agent_pid.trim().is_empty() || grant.address.trim().is_empty() {
        return Err("agent_pid_and_address_required".into());
    }
    crate::kernel::admission_layers::validate_grant_layers(
        &grant.layer,
        &grant.effect,
        &grant.app_allow,
        grant.justification.as_deref(),
    )?;

    let tenant = normalize_tenant(tenant_id);
    ensure_root_store(es, &tenant, "kernel")?;

    let legacy_key = world_gateway::grant_key(&grant.agent_pid, &grant.address);
    let grant_id = format!("grnt_{}", Uuid::new_v4().simple());

    let mut attenuation = None;
    if let Some(parent_id) = parent_grant_id {
        let parent: GrantRef = get_json(es, GRANT_REF_FOLDER, parent_id)?
            .ok_or_else(|| "parent_grant_not_found".to_string())?;
        if parent.revoked || get_json::<RevocationTombstone>(es, TOMBSTONE_FOLDER, parent_id)?.is_some()
        {
            return Err("parent_grant_revoked".into());
        }
        // Provisional child for attenuation check
        let provisional = GrantRef {
            schema: GRANT_REF_SCHEMA.into(),
            grant_id: grant_id.clone(),
            tenant_id: tenant.clone(),
            principal_id: grant.agent_pid.clone(),
            resource: grant.address.clone(),
            actions: grant.access.clone(),
            effect: grant.effect.clone(),
            layer: grant.layer.clone(),
            parent_grant_id: Some(parent_id.to_string()),
            attenuation_digest: None,
            legacy_world_grant_key: Some(legacy_key.clone()),
            minted_at_revision: 0,
            expires_at_ms: None,
            revoked: false,
            minted_at_ms: now_ms(),
        };
        if !attenuates_ok(&parent, &provisional) {
            return Err("attenuation_denied:child_not_subset_of_parent".into());
        }
        // Legacy WorldGrant cannot mint delegated children without GrantRef parent.
        attenuation = Some(attenuation_digest(&parent, &provisional));
    }

    let rev = bump_revision_store(es, &tenant, "mint", Some(grant_id.clone()))?;
    let gref = GrantRef {
        schema: GRANT_REF_SCHEMA.into(),
        grant_id: grant_id.clone(),
        tenant_id: tenant.clone(),
        principal_id: grant.agent_pid.clone(),
        resource: grant.address.clone(),
        actions: grant.access.clone(),
        effect: grant.effect.clone(),
        layer: grant.layer.clone(),
        parent_grant_id: parent_grant_id.map(|s| s.to_string()),
        attenuation_digest: attenuation,
        legacy_world_grant_key: Some(legacy_key.clone()),
        minted_at_revision: rev,
        expires_at_ms: None,
        revoked: false,
        minted_at_ms: now_ms(),
    };
    put_json(es, GRANT_REF_FOLDER, &grant_ref_key(&grant_id), &gref)?;
    put_json(
        es,
        GRANT_REF_FOLDER,
        &principal_index_key(&tenant, &grant.agent_pid, &grant.address),
        &json!({ "grant_id": grant_id }),
    )?;
    // Legacy dual-write
    es.folder_put(GRANT_FOLDER, &legacy_key, &serde_json::to_value(grant).unwrap_or(Value::Null))
        .map_err(|e| e.to_string())?;
    Ok((gref, rev))
}

pub fn mint_world_grant(
    state: &PlatformState,
    grant: &WorldGrantV1,
    tenant_id: Option<&str>,
    parent_grant_id: Option<&str>,
) -> Result<(GrantRef, u64), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let out = mint_world_grant_store(es.as_mut(), grant, tenant_id, parent_grant_id)?;
    drop(es);
    // Align in-memory ARC epoch with tenant revision bumps (best-effort).
    let _ = crate::substrate::arc::runtime::epochs().bump(&grant.agent_pid);
    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        &grant.agent_pid,
        "world.grant",
        true,
        &json!({
            "address": grant.address,
            "layer": grant.layer,
            "grant_id": out.0.grant_id,
            "authority_revision": out.1,
        }),
    );
    Ok(out)
}

/// Revoke: tombstone first, then mark GrantRef, then delete legacy WorldGrant.
pub fn revoke_world_grant_store(
    es: &mut dyn EngineStore,
    agent_pid: &str,
    address: &str,
    tenant_id: Option<&str>,
    reason: &str,
) -> Result<(Option<RevocationTombstone>, u64, bool), String> {
    let pid = agent_pid.trim();
    let addr = address.trim();
    if pid.is_empty() || addr.is_empty() {
        return Err("agent_pid_and_address_required".into());
    }
    let tenant = normalize_tenant(tenant_id);
    ensure_root_store(es, &tenant, "kernel")?;

    let legacy_key = world_gateway::grant_key(pid, addr);
    let idx_key = principal_index_key(&tenant, pid, addr);
    let grant_id = get_json::<Value>(es, GRANT_REF_FOLDER, &idx_key)?
        .and_then(|v| v.get("grant_id").and_then(|x| x.as_str()).map(str::to_string));

    let existed_legacy = es.folder_get(GRANT_FOLDER, &legacy_key).ok().flatten().is_some();

    let tombstone = if let Some(gid) = grant_id.clone() {
        let rev = bump_revision_store(es, &tenant, "revoke", Some(gid.clone()))?;
        let ts = RevocationTombstone {
            schema: TOMBSTONE_SCHEMA.into(),
            grant_id: gid.clone(),
            tenant_id: tenant.clone(),
            revoked_at_revision: rev,
            reason: reason.into(),
            at_ms: now_ms(),
        };
        // Tombstone BEFORE deleting legacy grant (deny-before-ACK).
        put_json(es, TOMBSTONE_FOLDER, &gid, &ts)?;
        if let Some(mut gref) = get_json::<GrantRef>(es, GRANT_REF_FOLDER, &gid)? {
            gref.revoked = true;
            put_json(es, GRANT_REF_FOLDER, &gid, &gref)?;
        }
        let _ = es.folder_delete(GRANT_FOLDER, &legacy_key);
        let _ = es.folder_delete(GRANT_REF_FOLDER, &idx_key);
        Ok((Some(ts), rev, existed_legacy || true))
    } else if existed_legacy {
        // Migration: legacy-only grant — still tombstone a synthetic id.
        let gid = format!("legacy_{}", legacy_key.replace(':', "_"));
        let rev = bump_revision_store(es, &tenant, "revoke", Some(gid.clone()))?;
        let ts = RevocationTombstone {
            schema: TOMBSTONE_SCHEMA.into(),
            grant_id: gid.clone(),
            tenant_id: tenant,
            revoked_at_revision: rev,
            reason: format!("{reason};legacy_world_grant"),
            at_ms: now_ms(),
        };
        put_json(es, TOMBSTONE_FOLDER, &gid, &ts)?;
        let _ = es.folder_delete(GRANT_FOLDER, &legacy_key);
        Ok((Some(ts), rev, true))
    } else {
        let rev = current_revision_store(es, &tenant);
        Ok((None, rev, false))
    };
    tombstone
}

pub fn revoke_world_grant(
    state: &PlatformState,
    agent_pid: &str,
    address: &str,
    tenant_id: Option<&str>,
    reason: &str,
) -> Result<Value, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let (ts, rev, existed) =
        revoke_world_grant_store(es.as_mut(), agent_pid, address, tenant_id, reason)?;
    drop(es);
    let _ = crate::substrate::arc::runtime::epochs().bump(agent_pid);
    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        agent_pid,
        "world.revoke",
        true,
        &json!({
            "address": address,
            "existed": existed,
            "authority_revision": rev,
            "tombstone": ts.as_ref().map(|t| t.grant_id.clone()),
        }),
    );
    Ok(json!({
        "ok": true,
        "grant_key": world_gateway::grant_key(agent_pid, address),
        "existed": existed,
        "authority_revision": rev,
        "tombstone_grant_id": ts.as_ref().map(|t| t.grant_id.clone()),
        "honesty": "Compensating — tombstone written before legacy grant delete. Not world rewind."
    }))
}

/// Resolve active GrantRef for principal × resource (empty if none / tombstoned).
pub fn resolve_grant_store(
    es: &dyn EngineStore,
    tenant_id: &str,
    principal_id: &str,
    resource: &str,
) -> Option<GrantRef> {
    let tenant = normalize_tenant(Some(tenant_id));
    let idx = principal_index_key(&tenant, principal_id, resource);
    let gid = get_json::<Value>(es, GRANT_REF_FOLDER, &idx)
        .ok()
        .flatten()
        .and_then(|v| v.get("grant_id")?.as_str().map(str::to_string))?;
    if get_json::<RevocationTombstone>(es, TOMBSTONE_FOLDER, &gid)
        .ok()
        .flatten()
        .is_some()
    {
        return None;
    }
    let g = get_json::<GrantRef>(es, GRANT_REF_FOLDER, &gid).ok().flatten()?;
    if g.revoked || !g.is_active_at(now_ms()) {
        return None;
    }
    Some(g)
}

pub fn resolve_grant(
    state: &PlatformState,
    tenant_id: Option<&str>,
    principal_id: &str,
    resource: &str,
) -> Option<GrantRef> {
    let tenant = normalize_tenant(tenant_id);
    let Ok(es) = state.engine_store.lock() else {
        return None;
    };
    resolve_grant_store(es.as_ref(), &tenant, principal_id, resource)
}

/// Binding for native envelopes: revision + optional grant id.
#[derive(Debug, Clone)]
pub struct AuthorityBinding {
    pub tenant_id: String,
    pub authority_revision: u64,
    pub grant_ref: String,
    pub root_id: String,
}

pub fn bind_for_invocation_store(
    es: &mut dyn EngineStore,
    tenant_id: Option<&str>,
    principal_id: Option<&str>,
    resource: Option<&str>,
) -> AuthorityBinding {
    let tenant = normalize_tenant(tenant_id);
    let root = ensure_root_store(es, &tenant, "kernel").ok();
    let rev = root
        .as_ref()
        .map(|r| r.current_revision)
        .unwrap_or_else(|| current_revision_store(es, &tenant));
    let grant_ref = match (principal_id, resource) {
        (Some(p), Some(r)) if !p.is_empty() && !r.is_empty() => {
            resolve_grant_store(es, &tenant, p, r)
                .map(|g| g.grant_id)
                .unwrap_or_default()
        }
        _ => String::new(),
    };
    AuthorityBinding {
        tenant_id: tenant,
        authority_revision: rev,
        grant_ref,
        root_id: root.map(|r| r.root_id).unwrap_or_else(|| format!("aroot_{}", normalize_tenant(tenant_id))),
    }
}

pub fn bind_for_invocation(
    state: &PlatformState,
    tenant_id: Option<&str>,
    principal_id: Option<&str>,
    resource: Option<&str>,
) -> AuthorityBinding {
    let Ok(mut es) = state.engine_store.lock() else {
        return AuthorityBinding {
            tenant_id: normalize_tenant(tenant_id),
            authority_revision: 0,
            grant_ref: String::new(),
            root_id: String::new(),
        };
    };
    bind_for_invocation_store(es.as_mut(), tenant_id, principal_id, resource)
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;

    fn sample_grant() -> WorldGrantV1 {
        WorldGrantV1 {
            agent_pid: "agent-a".into(),
            address: "https://api.example".into(),
            address_type: "http_api".into(),
            access: vec!["get".into(), "post".into()],
            effect: "ask".into(),
            layer: "cone".into(),
            app_allow: vec![],
            cone_ask: vec![],
            justification: None,
            params: Value::Null,
            note: None,
        }
    }

    #[test]
    fn mint_bumps_revision_and_dual_writes() {
        let mut es = InMemoryEngineStore::new();
        let g = sample_grant();
        let (gref, rev) = mint_world_grant_store(&mut es, &g, Some("t1"), None).unwrap();
        assert_eq!(rev, 1);
        assert_eq!(gref.minted_at_revision, 1);
        assert!(gref.legacy_world_grant_key.is_some());
        assert_eq!(current_revision_store(&es, "t1"), 1);
        let legacy = es
            .folder_get(GRANT_FOLDER, &world_gateway::grant_key("agent-a", "https://api.example"))
            .unwrap();
        assert!(legacy.is_some());
        let resolved = resolve_grant_store(&es, "t1", "agent-a", "https://api.example");
        assert_eq!(resolved.unwrap().grant_id, gref.grant_id);
    }

    #[test]
    fn revoke_writes_tombstone_before_delete() {
        let mut es = InMemoryEngineStore::new();
        let g = sample_grant();
        let (gref, _) = mint_world_grant_store(&mut es, &g, Some("t1"), None).unwrap();
        let (ts, rev, existed) =
            revoke_world_grant_store(&mut es, "agent-a", "https://api.example", Some("t1"), "test")
                .unwrap();
        assert!(existed);
        assert_eq!(rev, 2);
        let ts = ts.expect("tombstone");
        assert_eq!(ts.grant_id, gref.grant_id);
        assert_eq!(ts.revoked_at_revision, 2);
        let tomb = es.folder_get(TOMBSTONE_FOLDER, &gref.grant_id).unwrap();
        assert!(tomb.is_some());
        let legacy = es
            .folder_get(GRANT_FOLDER, &world_gateway::grant_key("agent-a", "https://api.example"))
            .unwrap();
        assert!(legacy.is_none());
        assert!(resolve_grant_store(&es, "t1", "agent-a", "https://api.example").is_none());
    }

    #[test]
    fn attenuation_requires_subset() {
        let mut es = InMemoryEngineStore::new();
        let parent = sample_grant();
        let (pref, _) = mint_world_grant_store(&mut es, &parent, Some("t1"), None).unwrap();
        let mut child = sample_grant();
        child.access = vec!["delete".into()]; // not in parent
        let err = mint_world_grant_store(&mut es, &child, Some("t1"), Some(&pref.grant_id));
        assert!(err.is_err());
        child.access = vec!["get".into()];
        let ok = mint_world_grant_store(&mut es, &child, Some("t1"), Some(&pref.grant_id));
        assert!(ok.is_ok());
        assert_eq!(current_revision_store(&es, "t1"), 2);
    }

    #[test]
    fn require_revision_fail_closed() {
        let mut es = InMemoryEngineStore::new();
        let _ = mint_world_grant_store(&mut es, &sample_grant(), Some("t1"), None).unwrap();
        assert!(require_revision_store(&es, "t1", 0).is_err());
        assert!(require_revision_store(&es, "t1", 99).is_err());
        assert_eq!(require_revision_store(&es, "t1", 1).unwrap(), 1);
    }

    #[test]
    fn bind_for_invocation_uses_real_revision() {
        let mut es = InMemoryEngineStore::new();
        let (gref, _) = mint_world_grant_store(&mut es, &sample_grant(), Some("t1"), None).unwrap();
        let bind = bind_for_invocation_store(
            &mut es,
            Some("t1"),
            Some("agent-a"),
            Some("https://api.example"),
        );
        assert_eq!(bind.authority_revision, 1);
        assert_eq!(bind.grant_ref, gref.grant_id);
        assert!(bind.root_id.starts_with("aroot_"));
    }
}
