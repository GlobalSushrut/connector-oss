//! Append-only usage event store (`billing_usage_events` namespace).

use connector_trust::{UsageEventV2, USAGE_EVENT_SCHEMA};

use crate::state::PlatformState;

pub const USAGE_EVENTS_FOLDER: &str = "billing_usage_events";

/// Persist one UsageEventV2 (SoT for books projections).
pub fn append_usage_event(state: &PlatformState, event: &UsageEventV2) -> String {
    debug_assert_eq!(event.schema, USAGE_EVENT_SCHEMA);
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(USAGE_EVENTS_FOLDER, &event.event_id, &serde_json::to_value(event).unwrap());
    event.event_id.clone()
}

pub fn usage_event_count(state: &PlatformState) -> usize {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys(USAGE_EVENTS_FOLDER, None)
        .map(|k| k.len())
        .unwrap_or(0)
}
