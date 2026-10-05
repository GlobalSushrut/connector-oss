//! Append-only artifact log segment store (I-13 / P6.3).

use connector_engine::engine_store::EngineStore;
use connector_trust::{ArtifactLogRecordV2, ARTIFACT_LOG_SCHEMA};
use serde_json::json;

use crate::state::PlatformState;

pub const ARTIFACT_LOG_FOLDER: &str = "artifact_log_v2";

/// Day-bucket segment id from `observed_at` (RFC3339 prefix `YYYY-MM-DD` → `seg_YYYYMMDD`).
pub fn segment_id_for_observed_at(observed_at: &str) -> String {
    let date = observed_at.get(..10).unwrap_or("");
    if date.len() == 10 && date.as_bytes()[4] == b'-' && date.as_bytes()[7] == b'-' {
        let compact: String = date.chars().filter(|c| *c != '-').collect();
        return format!("seg_{compact}");
    }
    "seg_unknown".into()
}

fn count_record_keys(es: &dyn EngineStore) -> usize {
    es.folder_keys(ARTIFACT_LOG_FOLDER, None)
        .map(|keys| keys.iter().filter(|k| !k.contains('/')).count())
        .unwrap_or(0)
}

fn append_to_store(es: &mut dyn EngineStore, record: &ArtifactLogRecordV2) -> String {
    debug_assert_eq!(record.schema, ARTIFACT_LOG_SCHEMA);
    let mut stored = record.clone();
    if stored.segment_id.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
        stored.segment_id = Some(segment_id_for_observed_at(&stored.observed_at));
    }
    let segment_id = stored.segment_id.clone().unwrap_or_else(|| "seg_unknown".into());
    // Store key remains record_id for existing readers; segment_id is on the payload
    // and mirrored under a segment index key for rebuild scans.
    let value = serde_json::to_value(&stored).unwrap_or(json!({}));
    let _ = es.folder_put(ARTIFACT_LOG_FOLDER, &stored.record_id, &value);
    let index_key = format!("{segment_id}/{}", stored.record_id);
    let _ = es.folder_put(
        ARTIFACT_LOG_FOLDER,
        &index_key,
        &json!({
            "schema": "artifact_log_segment_index.v1",
            "segment_id": segment_id,
            "record_id": stored.record_id,
        }),
    );
    stored.record_id.clone()
}

/// Append a record; ensures `segment_id` is set on the stored path/payload.
pub fn append_artifact_record(state: &PlatformState, record: &ArtifactLogRecordV2) -> String {
    let mut es = state.engine_store.lock().unwrap();
    append_to_store(&mut **es, record)
}

pub fn artifact_log_count(state: &PlatformState) -> usize {
    let es = state.engine_store.lock().unwrap();
    count_record_keys(&**es)
}

/// Recent top-level record ids for operator citation (P6.3 UI). Segment index keys excluded.
pub fn recent_artifact_record_ids(state: &PlatformState, limit: usize) -> Vec<String> {
    let es = state.engine_store.lock().unwrap();
    let mut keys = es
        .folder_keys(ARTIFACT_LOG_FOLDER, None)
        .unwrap_or_default()
        .into_iter()
        .filter(|k| !k.contains('/'))
        .collect::<Vec<_>>();
    keys.sort();
    keys.reverse();
    keys.into_iter().take(limit.max(1).min(32)).collect()
}

/// Stub projection rebuild: recount append-only record keys from the log (I-13 / P6.3).
/// Full segment materialize / soak remains open — this is the rebuild-from-log count contract.
pub fn rebuild_from_log(state: &PlatformState) -> usize {
    artifact_log_count(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::engine_store::InMemoryEngineStore;
    use connector_trust::ArtifactClass;
    use serde_json::json;

    #[test]
    fn segment_id_from_rfc3339_day_bucket() {
        assert_eq!(
            segment_id_for_observed_at("2026-08-08T15:04:05Z"),
            "seg_20260808"
        );
        assert_eq!(
            segment_id_for_observed_at("2026-01-02T00:00:00+00:00"),
            "seg_20260102"
        );
    }

    #[test]
    fn segment_id_unknown_when_unparseable() {
        assert_eq!(segment_id_for_observed_at("not-a-date"), "seg_unknown");
        assert_eq!(segment_id_for_observed_at(""), "seg_unknown");
    }

    #[test]
    fn rebuild_from_log_counts_two_appended_records() {
        let mut es = InMemoryEngineStore::new();
        let r1 = ArtifactLogRecordV2 {
            schema: ARTIFACT_LOG_SCHEMA.into(),
            record_id: "rec-a".into(),
            artifact_class: ArtifactClass::Operator,
            artifact_type: "unit_test".into(),
            observed_at: "2026-08-08T12:00:00Z".into(),
            segment_id: None,
            principal_id: None,
            tenant_id: None,
            content_digest: None,
            payload: json!({"n": 1}),
            contract_version: 2,
        };
        let mut r2 = r1.clone();
        r2.record_id = "rec-b".into();
        r2.observed_at = "2026-08-08T12:01:00Z".into();
        r2.payload = json!({"n": 2});
        append_to_store(&mut es, &r1);
        append_to_store(&mut es, &r2);
        // rebuild_from_log stub = recount record keys (segment index keys excluded).
        assert_eq!(count_record_keys(&es), 2);
    }
}
