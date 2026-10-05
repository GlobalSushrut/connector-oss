//! Channel observe + surface resolve + HTTP native invocation facade.
//!
//! Unknown destinations create `transport_only` surfaces (valid). Edge receipts
//! always record `enforcement_posture` and `semantic_confidence`.
//!
//! HTTP `POST /api/v1/native/invocations` routes exclusively through
//! [`crate::substrate::native_invoker`] (ActionBinding/PATE when eligible).
//! Migration-era stub PATE helpers exist only under `cfg(test)`.

use connector_engine::engine_store::EngineStore;
use connector_native_contract::{
    digest_hex_str, new_uid, ChannelDirection, ChannelObservation, ChannelRef, ChannelState,
    EdgeReceipt, Locator, ObservedIdentity, SemanticConfidence, SemanticProvenance,
    SemanticResolutionState, SurfaceRef, SurfaceRelation, TargetState, TransportObservation,
};
#[cfg(test)]
use connector_native_contract::{
    EffectDescriptor, EnforcementPosture, InvocationEnvelope, InvocationMode, InvocationOrigin,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};

pub const CHANNEL_FOLDER: &str = "channel_ref_v1";
pub const SURFACE_FOLDER: &str = "surface_ref_v1";
pub const RECEIPT_FOLDER: &str = "edge_receipt_v1";
pub const INVOCATION_FOLDER: &str = "invocation_envelope_v1";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub(crate) fn put_json(
    es: &mut dyn EngineStore,
    folder: &str,
    key: &str,
    value: &impl Serialize,
) -> Result<(), String> {
    let v = serde_json::to_value(value).map_err(|e| e.to_string())?;
    es.folder_put(folder, key, &v).map_err(|e| e.to_string())
}

pub(crate) fn get_json<T: for<'de> Deserialize<'de>>(
    es: &dyn EngineStore,
    folder: &str,
    key: &str,
) -> Option<T> {
    let v = es.folder_get(folder, key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn locator_surface_key(locator_value: &str) -> String {
    format!("loc:{}", digest_hex_str(locator_value))
}

fn is_trusted_provenance(p: &SemanticProvenance) -> bool {
    matches!(
        p,
        SemanticProvenance::SignedAdapter { .. }
            | SemanticProvenance::NativeCaller
            | SemanticProvenance::ProtocolDecoder { .. }
            | SemanticProvenance::OperatorDeclaration
    )
}

/// Observe a channel; always create/find a peer SurfaceRef (unknown = valid).
pub fn observe_channel_store(
    es: &mut dyn EngineStore,
    observation: ChannelObservation,
) -> Result<(ChannelRef, SurfaceRef), String> {
    let dest = observation
        .transport
        .destination
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".into());

    let scheme = if observation.transport.transport.is_empty() {
        "transport".into()
    } else {
        observation.transport.transport.clone()
    };

    let loc_key = locator_surface_key(&dest);
    let surface = if let Some(existing) = get_json::<SurfaceRef>(es, SURFACE_FOLDER, &loc_key) {
        existing
    } else {
        let mut confidence = SemanticConfidence::TransportOnly;
        let mut provenance = SemanticProvenance::KernelObservation;
        let mut semantic_state = SemanticResolutionState::Unresolved;
        let mut relation = SurfaceRelation::Unknown;

        // Hints may enrich initial observation without claiming authority.
        if let Some(hint_conf) = observation
            .raw_hints
            .get("semantic_confidence")
            .and_then(|v| serde_json::from_value::<SemanticConfidence>(v.clone()).ok())
        {
            confidence = hint_conf;
        }
        if let Some(hint_prov) = observation
            .raw_hints
            .get("provenance")
            .and_then(|v| serde_json::from_value::<SemanticProvenance>(v.clone()).ok())
        {
            provenance = hint_prov;
        }
        if let Some(hint_rel) = observation
            .raw_hints
            .get("relation")
            .and_then(|v| serde_json::from_value::<SurfaceRelation>(v.clone()).ok())
        {
            relation = hint_rel;
        }
        if confidence.rank() > SemanticConfidence::TransportOnly.rank() {
            semantic_state = SemanticResolutionState::TransportObserved;
        }

        let surface = SurfaceRef {
            surface_uid: new_uid("surf_"),
            relation,
            observed_identity: Some(ObservedIdentity {
                kind: "destination".into(),
                value: dest.clone(),
            }),
            locators: vec![Locator {
                scheme,
                value: dest.clone(),
                digest: Some(digest_hex_str(&dest)),
            }],
            semantic_state,
            confidence,
            interfaces: vec![],
            provenance,
            revision: 1,
        };
        put_json(es, SURFACE_FOLDER, &surface.surface_uid, &surface)?;
        put_json(es, SURFACE_FOLDER, &loc_key, &surface)?;
        surface
    };

    let tenant = crate::substrate::target_catalog::tenant_from_hints(&observation.raw_hints);

    let channel = ChannelRef {
        channel_uid: new_uid("ch_"),
        origin_intelligence: observation.origin_intelligence,
        origin_workload: observation.origin_workload,
        direction: observation.direction,
        transport: observation.transport,
        peer: Some(surface.surface_uid.clone()),
        contract_revision: 1,
        authority_revision: 1,
        semantic_confidence: surface.confidence,
        state: ChannelState::Observed,
    };
    put_json(es, CHANNEL_FOLDER, &channel.channel_uid, &channel)?;

    // Index into tenant catalog (discovery only — never grants authority).
    let _ = crate::substrate::target_catalog::index_surface_store(es, &surface, Some(&tenant), None);
    let _ = crate::substrate::target_catalog::index_channel_store(es, &channel, Some(&tenant));

    Ok((channel, surface))
}

pub fn observe_channel(
    state: &PlatformState,
    observation: ChannelObservation,
) -> Result<(ChannelRef, SurfaceRef), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    observe_channel_store(es.as_mut(), observation)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichSurfaceRequest {
    pub confidence: SemanticConfidence,
    pub provenance: SemanticProvenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<SurfaceRelation>,
}

/// Monotonic surface enrichment.
///
/// Upgrading confidence is allowed for semantics when the new rank is higher
/// AND provenance is trusted. Authority checks must still use the narrower
/// grant — this function documents that in returned confidence.
/// Conflicting adapter claims merge via `SemanticConfidence::narrower`.
pub fn enrich_surface_store(
    es: &mut dyn EngineStore,
    surface_uid: &str,
    confidence: SemanticConfidence,
    provenance: SemanticProvenance,
    relation: Option<SurfaceRelation>,
) -> Result<SurfaceRef, String> {
    let mut surface: SurfaceRef = get_json(es, SURFACE_FOLDER, surface_uid)
        .ok_or_else(|| "surface_not_found".to_string())?;

    let old = surface.confidence;
    let new = confidence;

    // Track prior adapter claim for conflict detection.
    let conflict = match (&surface.provenance, &provenance) {
        (
            SemanticProvenance::SignedAdapter { adapter_ref: a },
            SemanticProvenance::SignedAdapter { adapter_ref: b },
        ) if a != b && old != new => true,
        (
            SemanticProvenance::ProtocolDecoder { decoder_ref: a },
            SemanticProvenance::ProtocolDecoder { decoder_ref: b },
        ) if a != b && old != new => true,
        _ => false,
    };

    if conflict {
        surface.confidence = SemanticConfidence::narrower(old, new);
    } else if new.rank() > old.rank() && is_trusted_provenance(&provenance) {
        surface.confidence = new;
        surface.provenance = provenance.clone();
    } else if new.rank() < old.rank() {
        // Never widen authority on conflict — take narrower.
        surface.confidence = SemanticConfidence::narrower(old, new);
    } else if new.rank() == old.rank() && is_trusted_provenance(&provenance) {
        surface.provenance = provenance.clone();
    }
    // else: ignore untrusted upgrade attempts (keep old)

    if let Some(rel) = relation {
        surface.relation = rel;
    }

    surface.semantic_state = match surface.confidence {
        SemanticConfidence::TransportOnly => SemanticResolutionState::TransportObserved,
        SemanticConfidence::ProtocolObserved => SemanticResolutionState::ProtocolObserved,
        SemanticConfidence::AdapterVerified => SemanticResolutionState::AdapterVerified,
        SemanticConfidence::NativeVerified => SemanticResolutionState::NativeVerified,
    };
    surface.revision = surface.revision.saturating_add(1);

    put_json(es, SURFACE_FOLDER, &surface.surface_uid, &surface)?;
    // Refresh locator index if present.
    if let Some(loc) = surface.locators.first() {
        put_json(es, SURFACE_FOLDER, &locator_surface_key(&loc.value), &surface)?;
    }
    let tenant = crate::substrate::target_catalog::tenant_for_surface_store(es, &surface.surface_uid)
        .unwrap_or_else(|| "default".into());
    let _ = crate::substrate::target_catalog::index_surface_store(es, &surface, Some(&tenant), None);
    Ok(surface)
}

pub fn enrich_surface(
    state: &PlatformState,
    surface_uid: &str,
    confidence: SemanticConfidence,
    provenance: SemanticProvenance,
    relation: Option<SurfaceRelation>,
) -> Result<SurfaceRef, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    enrich_surface_store(es.as_mut(), surface_uid, confidence, provenance, relation)
}

#[cfg(test)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInvocationRequest {
    pub origin: InvocationOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_uid: Option<String>,
    pub effect: EffectDescriptor,
    pub contract_ref: String,
    #[serde(default)]
    pub authority_ref: String,
    #[serde(default)]
    pub lifecycle_mode: InvocationMode,
    /// Optional workload enforcement posture for the receipt (default Advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_posture: Option<EnforcementPosture>,
}

/// Test-only migration-era admission stub (not production PATE).
///
/// Production invokes go through [`crate::substrate::native_invoker`].
#[cfg(test)]
pub fn stub_pate_verdict(
    confidence: SemanticConfidence,
    mutates: bool,
) -> (&'static str, &'static str, &'static str) {
    // (pate_verdict, execution_state, honesty)
    match (confidence, mutates) {
        (SemanticConfidence::TransportOnly, true) => (
            "deny",
            "denied",
            "deny-by-default: transport_only/unknown surfaces cannot mutate until resolved",
        ),
        (SemanticConfidence::TransportOnly, false) => (
            "allow_narrow",
            "admitted_narrow",
            "transport_only read/observe allowed narrowly; not full PATE admission",
        ),
        _ if mutates && confidence.rank() < SemanticConfidence::AdapterVerified.rank() => (
            "deny",
            "denied",
            "deny-by-default: mutations require AdapterVerified+ semantics in migration stub",
        ),
        _ => (
            "migration_recorded",
            "recorded",
            "envelope+receipt recorded; ActionBinding/PATE not fully replaced yet",
        ),
    }
}

#[cfg(test)]
pub fn build_invocation_store(
    es: &mut dyn EngineStore,
    req: BuildInvocationRequest,
) -> Result<(InvocationEnvelope, EdgeReceipt, Value), String> {
    let (surface, confidence, provenance) = if let Some(ref sid) = req.surface_uid {
        let s: SurfaceRef =
            get_json(es, SURFACE_FOLDER, sid).ok_or_else(|| "surface_not_found".to_string())?;
        let conf = s.confidence;
        let prov = s.provenance.clone();
        (Some(s), conf, prov)
    } else {
        (
            None,
            SemanticConfidence::TransportOnly,
            SemanticProvenance::KernelObservation,
        )
    };

    let target = if let Some(ref s) = surface {
        TargetState::Surface {
            surface_uid: s.surface_uid.clone(),
        }
    } else {
        TargetState::Unresolved {
            observed_peer: ObservedIdentity {
                kind: "unknown".into(),
                value: "unspecified".into(),
            },
        }
    };

    let invocation_id = new_uid("inv_");
    let envelope = InvocationEnvelope {
        invocation_id: invocation_id.clone(),
        origin: req.origin.clone(),
        target,
        semantic_provenance: provenance.clone(),
        semantic_confidence: confidence,
        action: None,
        effect: req.effect.clone(),
        contract_ref: req.contract_ref.clone(),
        contract_revision: 1,
        authority_ref: if req.authority_ref.is_empty() {
            "authority:migration_stub".into()
        } else {
            req.authority_ref.clone()
        },
        authority_revision: 1,
        channel_ref: req.channel_uid.clone(),
        surface_ref: req.surface_uid.clone(),
        lifecycle_mode: req.lifecycle_mode,
        deadline_ms: None,
    };
    put_json(es, INVOCATION_FOLDER, &invocation_id, &envelope)?;

    let (pate_verdict, execution_state, honesty) =
        stub_pate_verdict(confidence, req.effect.mutates);
    let enforcement_posture = req
        .enforcement_posture
        .unwrap_or(EnforcementPosture::Advisory);

    let receipt = EdgeReceipt {
        operation_id: invocation_id.clone(),
        intelligence_uid: req.origin.intelligence_uid.clone(),
        workload_uid: req.origin.workload_uid.clone(),
        software_uid: req.origin.software_uid.clone(),
        channel_uid: req.channel_uid.clone(),
        surface_uid: req.surface_uid.clone(),
        semantic_confidence: confidence,
        semantic_provenance: provenance,
        enforcement_posture,
        target_ref: None,
        observed_locators: surface
            .as_ref()
            .map(|s| {
                s.locators
                    .iter()
                    .filter_map(|l| l.digest.clone())
                    .collect()
            })
            .unwrap_or_default(),
        action_digest: None,
        effect_digest: Some(digest_hex_str(&format!(
            "{}|{}",
            req.effect.effect_class, req.effect.mutates
        ))),
        projection_digest: None,
        projection_loss_digest: None,
        contract_ref: req.contract_ref,
        contract_revision: 1,
        grant_ref: envelope.authority_ref.clone(),
        authority_revision: 1,
        pate_verdict: pate_verdict.into(),
        execution_state: execution_state.into(),
        evidence_refs: vec![format!("invocation:{invocation_id}")],
        issued_at_ms: now_ms(),
    };
    put_json(es, RECEIPT_FOLDER, &receipt.operation_id, &receipt)?;

    let meta = json!({
        "honesty": honesty,
        "pate_note": "cfg(test) facade only — production uses native_invoker",
    });
    Ok((envelope, receipt, meta))
}

#[cfg(test)]
pub fn build_invocation(
    state: &PlatformState,
    req: BuildInvocationRequest,
) -> Result<(InvocationEnvelope, EdgeReceipt, Value), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    build_invocation_store(es.as_mut(), req)
}

pub fn commit_edge_receipt_store(
    es: &mut dyn EngineStore,
    receipt: &EdgeReceipt,
) -> Result<EdgeReceipt, String> {
    put_json(es, RECEIPT_FOLDER, &receipt.operation_id, receipt)?;
    let _ = crate::substrate::evidence_graph::index_receipt(es, receipt);
    Ok(receipt.clone())
}

pub fn commit_edge_receipt(
    state: &PlatformState,
    receipt: &EdgeReceipt,
) -> Result<EdgeReceipt, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    commit_edge_receipt_store(es.as_mut(), receipt)
}

pub fn get_receipt_store(es: &dyn EngineStore, operation_id: &str) -> Option<EdgeReceipt> {
    get_json(es, RECEIPT_FOLDER, operation_id)
}

pub fn get_receipt(state: &PlatformState, operation_id: &str) -> Option<EdgeReceipt> {
    let es = state.engine_store.lock().ok()?;
    get_receipt_store(es.as_ref(), operation_id)
}

// ── HTTP handlers ──────────────────────────────────────────────────────────

pub async fn post_observe_channel(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(observation): axum::Json<ChannelObservation>,
) -> axum::Json<Value> {
    match observe_channel(state.as_ref(), observation) {
        Ok((channel, surface)) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "channel": channel,
            "surface": surface,
            "honesty": "Unknown destinations create transport_only surfaces; unknown is valid.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn post_resolve_surface(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<EnrichSurfaceRequest>,
) -> axum::Json<Value> {
    match enrich_surface(
        state.as_ref(),
        &id,
        req.confidence,
        req.provenance,
        req.relation,
    ) {
        Ok(surface) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "surface": surface,
            "honesty": "Confidence upgrades are semantic; authority checks must still use the narrower grant.",
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn post_invocation(
    axum::extract::State(state): axum::extract::State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::Json(mut req): axum::Json<crate::substrate::native_invoker::NativeInvokeRequest>,
) -> axum::Json<Value> {
    if let Some(reason) = crate::substrate::outbound::spoofed_identity_headers(&headers) {
        return axum::Json(crate::substrate::package_gate::deny_json(reason));
    }
    // JWT-bound tenant wins; reject body/header spoof when claims disagree.
    match crate::substrate::outbound::verified_tenant_id(&headers) {
        Some(tid) => {
            if let Some(body_tid) = req
                .tenant_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if body_tid != tid.as_str() {
                    return axum::Json(crate::substrate::package_gate::deny_json(
                        "tenant_spoof: body tenant_id disagrees with verified JWT",
                    ));
                }
            }
            req.tenant_id = Some(tid);
        }
        None => {
            if crate::connector_profile::is_productionish_env()
                && !crate::services::runtime_control::dev_auth_bypass_allowed()
            {
                return axum::Json(crate::substrate::package_gate::deny_json(
                    "tenant_required: verified JWT tenant binding missing",
                ));
            }
        }
    }
    match crate::substrate::native_invoker::invoke(&state, req) {
        Ok(result) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "invocation": result.envelope,
            "receipt": result.receipt,
            "pate_verdict": result.pate_verdict,
            "action_digest": result.action_digest,
            "flow_id": result.flow_id,
            "honesty": result.meta.get("honesty").cloned().unwrap_or(json!("native_invoker")),
            "pate_note": result.meta.get("pate_note"),
            "meta": result.meta,
        }))),
        Err(e) => axum::Json(crate::substrate::package_gate::deny_json(&e)),
    }
}

pub async fn get_receipt_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(operation_id): axum::extract::Path<String>,
) -> axum::Json<Value> {
    match get_receipt(state.as_ref(), &operation_id) {
        Some(r) => axum::Json(crate::operator::honesty::measured_envelope(
            serde_json::to_value(r).unwrap_or(json!({})),
        )),
        None => axum::Json(json!({
            "ok": false,
            "error": "receipt_not_found",
            "operation_id": operation_id,
        })),
    }
}

pub async fn get_evidence_graph(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::Json<Value> {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(64usize)
        .min(256);
    let intel = q.get("intelligence").map(|s| s.as_str());
    let es = match state.engine_store.lock() {
        Ok(g) => g,
        Err(_) => return axum::Json(json!({ "ok": false, "error": "engine_store_lock" })),
    };
    axum::Json(crate::operator::honesty::measured_envelope(
        crate::substrate::evidence_graph::graph_snapshot(es.as_ref(), intel, limit),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;

    fn unknown_obs(dest: &str) -> ChannelObservation {
        ChannelObservation {
            origin_intelligence: "intel_1".into(),
            origin_workload: "wl_1".into(),
            direction: ChannelDirection::Outbound,
            transport: TransportObservation {
                transport: "tcp".into(),
                destination: Some(dest.into()),
                port: Some(443),
                ..Default::default()
            },
            observed_at_ms: now_ms(),
            raw_hints: json!({}),
        }
    }

    #[test]
    fn observe_unknown_host_transport_only() {
        let mut es = InMemoryEngineStore::new();
        let (_ch, surface) =
            observe_channel_store(&mut es, unknown_obs("api.unknown.example")).expect("observe");
        assert_eq!(surface.confidence, SemanticConfidence::TransportOnly);
        assert!(matches!(
            surface.provenance,
            SemanticProvenance::KernelObservation
        ));
        assert!(matches!(
            surface.semantic_state,
            SemanticResolutionState::Unresolved | SemanticResolutionState::TransportObserved
        ));
    }

    #[test]
    fn enrich_signed_adapter_upgrades_to_adapter_verified() {
        let mut es = InMemoryEngineStore::new();
        let (_ch, surface) =
            observe_channel_store(&mut es, unknown_obs("svc.example")).expect("observe");
        let upgraded = enrich_surface_store(
            &mut es,
            &surface.surface_uid,
            SemanticConfidence::AdapterVerified,
            SemanticProvenance::SignedAdapter {
                adapter_ref: "adapter:http".into(),
            },
            Some(SurfaceRelation::WorldRead),
        )
        .expect("enrich");
        assert_eq!(upgraded.confidence, SemanticConfidence::AdapterVerified);
        assert_eq!(upgraded.relation, SurfaceRelation::WorldRead);
    }

    #[test]
    fn conflicting_adapter_upgrades_use_narrower() {
        let mut es = InMemoryEngineStore::new();
        let (_ch, surface) =
            observe_channel_store(&mut es, unknown_obs("conflict.example")).expect("observe");
        let first = enrich_surface_store(
            &mut es,
            &surface.surface_uid,
            SemanticConfidence::AdapterVerified,
            SemanticProvenance::SignedAdapter {
                adapter_ref: "adapter:a".into(),
            },
            None,
        )
        .expect("first");
        assert_eq!(first.confidence, SemanticConfidence::AdapterVerified);

        let second = enrich_surface_store(
            &mut es,
            &surface.surface_uid,
            SemanticConfidence::NativeVerified,
            SemanticProvenance::SignedAdapter {
                adapter_ref: "adapter:b".into(),
            },
            None,
        )
        .expect("second");
        // Conflicting adapters → narrower(AdapterVerified, NativeVerified) = AdapterVerified
        assert_eq!(
            second.confidence,
            SemanticConfidence::narrower(
                SemanticConfidence::AdapterVerified,
                SemanticConfidence::NativeVerified
            )
        );
    }

    #[test]
    fn invocation_transport_only_mutation_denied() {
        let mut es = InMemoryEngineStore::new();
        let (_ch, surface) =
            observe_channel_store(&mut es, unknown_obs("mutate.example")).expect("observe");
        let (_env, receipt, meta) = build_invocation_store(
            &mut es,
            BuildInvocationRequest {
                origin: InvocationOrigin {
                    software_uid: Some("sw_1".into()),
                    workload_uid: "wl_1".into(),
                    intelligence_uid: "intel_1".into(),
                    principal: "p".into(),
                },
                surface_uid: Some(surface.surface_uid),
                channel_uid: None,
                effect: EffectDescriptor {
                    effect_class: "write".into(),
                    mutates: true,
                    disclosure_class: None,
                },
                contract_ref: "contract:v1".into(),
                authority_ref: String::new(),
                lifecycle_mode: InvocationMode::Call,
                enforcement_posture: Some(EnforcementPosture::Advisory),
            },
        )
        .expect("invoke");
        assert_eq!(receipt.pate_verdict, "deny");
        assert_eq!(receipt.execution_state, "denied");
        assert_eq!(
            receipt.semantic_confidence,
            SemanticConfidence::TransportOnly
        );
        assert_eq!(receipt.enforcement_posture, EnforcementPosture::Advisory);
        assert!(meta.get("honesty").is_some());
    }

    #[test]
    fn observe_dedupes_by_locator() {
        let mut es = InMemoryEngineStore::new();
        let (_c1, s1) =
            observe_channel_store(&mut es, unknown_obs("same.host")).expect("o1");
        let (_c2, s2) =
            observe_channel_store(&mut es, unknown_obs("same.host")).expect("o2");
        assert_eq!(s1.surface_uid, s2.surface_uid);
    }
}
