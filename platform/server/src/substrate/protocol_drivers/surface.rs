//! Observe + enrich surfaces for protocol drivers.

use connector_engine::engine_store::EngineStore;
use connector_native_contract::{
    ChannelDirection, ChannelObservation, ProtocolDriverId, SemanticConfidence, SemanticProvenance,
    SurfaceRelation, TransportObservation,
};
use serde_json::json;

use crate::state::PlatformState;
use crate::substrate::channel_surface::{self, enrich_surface_store, observe_channel_store};

#[derive(Debug, Clone)]
pub struct BindSurfaceOpts {
    pub protocol: ProtocolDriverId,
    pub agent_pid: String,
    pub locator: String,
    pub confidence: SemanticConfidence,
    pub destination: Option<String>,
    pub port: Option<u16>,
    pub transport: String,
}

#[derive(Debug, Clone)]
pub struct BoundSurface {
    pub channel_uid: String,
    pub surface_uid: String,
    pub confidence: SemanticConfidence,
}

pub fn bind_protocol_surface_store(
    es: &mut dyn EngineStore,
    opts: BindSurfaceOpts,
) -> Result<BoundSurface, String> {
    let now = chrono::Utc::now().timestamp_millis();
    let obs = ChannelObservation {
        origin_intelligence: opts.agent_pid.clone(),
        origin_workload: format!("wl:protocol:{}", opts.protocol.as_str()),
        direction: ChannelDirection::Outbound,
        transport: TransportObservation {
            transport: opts.transport.clone(),
            destination: opts.destination.clone(),
            port: opts.port,
            ..Default::default()
        },
        observed_at_ms: now,
        raw_hints: json!({
            "protocol": opts.protocol.as_str(),
            "decoder_ref": opts.protocol.decoder_ref(),
            "locator": opts.locator,
            "tenant_id": "default",
        }),
    };
    let (channel, surface) = observe_channel_store(es, obs)?;

    let target_confidence = opts.confidence;
    let provenance = SemanticProvenance::ProtocolDecoder {
        decoder_ref: opts.protocol.decoder_ref().into(),
    };
    let surface = if target_confidence.rank() > surface.confidence.rank() {
        enrich_surface_store(
            es,
            &surface.surface_uid,
            target_confidence,
            provenance,
            Some(SurfaceRelation::WorldWrite),
        )?
    } else if matches!(
        target_confidence,
        SemanticConfidence::ProtocolObserved | SemanticConfidence::AdapterVerified
    ) {
        enrich_surface_store(
            es,
            &surface.surface_uid,
            target_confidence,
            provenance,
            Some(SurfaceRelation::WorldWrite),
        )?
    } else {
        surface
    };

    Ok(BoundSurface {
        channel_uid: channel.channel_uid,
        surface_uid: surface.surface_uid,
        confidence: surface.confidence,
    })
}

pub fn bind_protocol_surface(
    state: &PlatformState,
    opts: BindSurfaceOpts,
) -> Result<BoundSurface, String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    bind_protocol_surface_store(es.as_mut(), opts)
}

// Re-export for callers that already hold PlatformState helpers.
#[allow(dead_code)]
pub fn enrich_only(
    state: &PlatformState,
    surface_uid: &str,
    protocol: ProtocolDriverId,
    confidence: SemanticConfidence,
) -> Result<(), String> {
    channel_surface::enrich_surface(
        state,
        surface_uid,
        confidence,
        SemanticProvenance::ProtocolDecoder {
            decoder_ref: protocol.decoder_ref().into(),
        },
        Some(SurfaceRelation::WorldWrite),
    )
    .map(|_| ())
}
