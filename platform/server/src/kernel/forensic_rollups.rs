//! Hourly forensic rollups + correlation joins — high-volume preservation (P10.10.6).

use connector_trust::{
    ArtifactClass, ArtifactLogRecordV2, ARTIFACT_LOG_SCHEMA, ForensicCorrelationJoinV2,
    ForensicRollupBucketV2, ForensicRollupCountsV2, ForensicRollupMemoryTraceV2,
    FORENSIC_CORRELATION_SCHEMA, FORENSIC_ROLLUP_SCHEMA, FourIdLinkageV2,
};
use sha2::{Digest, Sha256};

use crate::kernel::forensics;
use crate::state::PlatformState;

pub const ROLLUP_FOLDER: &str = "forensic_rollup_bucket_v2";
pub const JOIN_FOLDER: &str = "forensic_correlation_join_v2";

#[derive(Debug, Clone)]
pub struct RollupEvent<'a> {
    pub agent_pid: &'a str,
    pub event_kind: &'a str,
    pub leaf_digest: String,
    pub universal_envelope_id: Option<String>,
    pub namespace: Option<&'a str>,
    pub cross_agent_denied: bool,
    pub admission_deny: bool,
    pub continuity_break: bool,
    pub quarantine: bool,
    pub egress_isolated: bool,
    pub cpo_id: Option<String>,
    pub quantum_id: Option<String>,
    pub docklock_profile_id: Option<String>,
    pub intelligence_receipt_id: Option<String>,
    pub witnessctl_session_id: Option<String>,
    pub tracetramp_trace_id: Option<String>,
    pub fni_flow_id: Option<String>,
    pub moment_id: Option<String>,
}

fn hour_bucket(ms: i64) -> (i64, i64, String) {
    let hour_ms = 3_600_000_i64;
    let start = (ms / hour_ms) * hour_ms;
    let end = start + hour_ms;
    let dt = chrono::DateTime::from_timestamp_millis(start)
        .unwrap_or_else(|| chrono::Utc::now());
    let label = dt.format("%Y%m%d%H").to_string();
    (start, end, label)
}

fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return hex::encode(Sha256::digest(b"empty"));
    }
    let mut layer: Vec<[u8; 32]> = leaves
        .iter()
        .map(|l| {
            let d = Sha256::digest(l.as_bytes());
            let mut a = [0u8; 32];
            a.copy_from_slice(&d);
            a
        })
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            let mut h = Sha256::new();
            h.update(chunk[0]);
            if chunk.len() == 2 {
                h.update(chunk[1]);
            } else {
                h.update(chunk[0]); // odd leaf: hash with self
            }
            let d = h.finalize();
            let mut a = [0u8; 32];
            a.copy_from_slice(&d);
            next.push(a);
        }
        layer = next;
    }
    hex::encode(layer[0])
}

fn bump_count(counts: &mut ForensicRollupCountsV2, kind: &str) {
    match kind {
        "n4.cognize" | "n4_cognize" | "cognize" => counts.n4_cognize += 1,
        "qpr.intent" | "qpr_intent" | "intent" => counts.qpr_intent += 1,
        "memory.write" | "memory_write" => counts.memory_write += 1,
        "gateway.turn" | "gateway_turn" | "llm.chat" => counts.gateway_turn += 1,
        "tool.dispatch" | "tool_dispatch" | "mcp.call" => counts.tool_dispatch += 1,
        "activate" => counts.activate += 1,
        "universal_envelope" | "activate_envelope" => counts.universal_envelope += 1,
        "intelligence_receipt" | "receipt" => counts.intelligence_receipt += 1,
        _ => {}
    }
}

pub fn record_event(state: &PlatformState, ev: RollupEvent<'_>) -> ForensicRollupBucketV2 {
    let now = chrono::Utc::now().timestamp_millis();
    let (start, end, label) = hour_bucket(now);
    let bucket_id = format!("rollup:{}:{}", ev.agent_pid, label);

    let mut bucket = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(ROLLUP_FOLDER, &bucket_id)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value::<ForensicRollupBucketV2>(v).ok())
            .unwrap_or_else(|| ForensicRollupBucketV2 {
                schema: FORENSIC_ROLLUP_SCHEMA.into(),
                bucket_id: bucket_id.clone(),
                agent_pid: ev.agent_pid.to_string(),
                window_start_ms: start,
                window_end_ms: end,
                counts: ForensicRollupCountsV2::default(),
                events_merkle_root: String::new(),
                first_universal_envelope_id: None,
                last_universal_envelope_id: None,
                iia_chain_head_at_close: None,
                memory_trace: ForensicRollupMemoryTraceV2::default(),
                hitl_pending_peak: 0,
                quarantine_events: 0,
                egress_isolated: false,
                leaf_digests: Vec::new(),
                closed: false,
                updated_at_ms: now,
            })
    };

    bump_count(&mut bucket.counts, ev.event_kind);
    if ev.admission_deny {
        bucket.counts.admission_deny += 1;
    }
    if ev.continuity_break {
        bucket.counts.continuity_break += 1;
    }
    if ev.quarantine {
        bucket.quarantine_events += 1;
    }
    if ev.egress_isolated {
        bucket.egress_isolated = true;
    }
    if ev.cross_agent_denied {
        bucket.memory_trace.cross_agent_attempts_denied += 1;
    }
    if let Some(ns) = ev.namespace {
        if !bucket
            .memory_trace
            .namespaces_touched
            .iter()
            .any(|n| n == ns)
        {
            bucket.memory_trace.namespaces_touched.push(ns.to_string());
        }
        bucket.memory_trace.packet_cid_count += 1;
    }
    if let Some(ref id) = ev.universal_envelope_id {
        if bucket.first_universal_envelope_id.is_none() {
            bucket.first_universal_envelope_id = Some(id.clone());
        }
        bucket.last_universal_envelope_id = Some(id.clone());
        bucket.counts.universal_envelope += 1;
    }

    // Cap stored leaves (Merkle still covers all by folding digest into running root).
    const MAX_LEAVES: usize = 4096;
    if bucket.leaf_digests.len() < MAX_LEAVES {
        bucket.leaf_digests.push(ev.leaf_digest.clone());
    } else {
        // Fold overflow into last leaf so root remains a function of all events.
        let mut h = Sha256::new();
        h.update(bucket.leaf_digests.last().unwrap().as_bytes());
        h.update(ev.leaf_digest.as_bytes());
        *bucket.leaf_digests.last_mut().unwrap() = hex::encode(h.finalize());
    }
    bucket.events_merkle_root = merkle_root(&bucket.leaf_digests);
    bucket.iia_chain_head_at_close = forensics::chain_head_for_agent(state, ev.agent_pid);
    bucket.updated_at_ms = now;

    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(ROLLUP_FOLDER, &bucket_id, &serde_json::to_value(&bucket).unwrap());
    }

    // Correlation join row
    if let Some(four_id) = forensics::four_id_linkage(state, ev.agent_pid) {
        let join = ForensicCorrelationJoinV2 {
            schema: FORENSIC_CORRELATION_SCHEMA.into(),
            join_id: format!("fj_{}", uuid::Uuid::new_v4()),
            agent_pid: ev.agent_pid.to_string(),
            principal_id: four_id.agent_id.clone(),
            four_id,
            cpo_id: ev.cpo_id.clone(),
            quantum_id: ev.quantum_id.clone(),
            docklock_profile_id: ev.docklock_profile_id.clone(),
            intelligence_receipt_id: ev.intelligence_receipt_id.clone(),
            universal_envelope_id: ev.universal_envelope_id.clone(),
            witnessctl_session_id: ev.witnessctl_session_id.clone(),
            tracetramp_trace_id: ev.tracetramp_trace_id.clone(),
            fni_flow_id: ev.fni_flow_id.clone(),
            moment_id: ev.moment_id.clone(),
            rollup_bucket_id: Some(bucket_id.clone()),
            event_kind: ev.event_kind.to_string(),
            issued_at_ms: now,
        };
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(JOIN_FOLDER, &join.join_id, &serde_json::to_value(&join).unwrap());
    }

    // Hourly segment proof into artifact log (content = merkle root).
    let observed = chrono::Utc::now().to_rfc3339();
    let _ = crate::substrate::artifact_log::append_artifact_record(
        state,
        &ArtifactLogRecordV2 {
            schema: ARTIFACT_LOG_SCHEMA.into(),
            record_id: format!("al_rollup_{}_{}", ev.agent_pid, now),
            artifact_class: ArtifactClass::Proof,
            artifact_type: "forensic_rollup_update".into(),
            observed_at: observed,
            segment_id: Some(format!("seg_{}", &label[..8.min(label.len())])),
            principal_id: Some(ev.agent_pid.to_string()),
            tenant_id: None,
            content_digest: Some(bucket.events_merkle_root.clone()),
            payload: serde_json::json!({
                "bucket_id": bucket.bucket_id,
                "event_kind": ev.event_kind,
                "merkle_root": bucket.events_merkle_root,
            }),
            contract_version: 2,
        },
    );

    bucket
}

pub fn list_rollups(
    state: &PlatformState,
    api_pid: &str,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Vec<ForensicRollupBucketV2> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(ROLLUP_FOLDER, None).unwrap_or_default();
    let mut out: Vec<ForensicRollupBucketV2> = keys
        .into_iter()
        .filter_map(|k| {
            let v = es.folder_get(ROLLUP_FOLDER, &k).ok().flatten()?;
            let b: ForensicRollupBucketV2 = serde_json::from_value(v).ok()?;
            if b.agent_pid != api_pid {
                return None;
            }
            if let Some(f) = from_ms {
                if b.window_end_ms < f {
                    return None;
                }
            }
            if let Some(t) = to_ms {
                if b.window_start_ms > t {
                    return None;
                }
            }
            Some(b)
        })
        .collect();
    out.sort_by_key(|b| b.window_start_ms);
    out
}

pub fn list_joins(state: &PlatformState, api_pid: &str) -> Vec<ForensicCorrelationJoinV2> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(JOIN_FOLDER, None).unwrap_or_default();
    let mut out: Vec<ForensicCorrelationJoinV2> = keys
        .into_iter()
        .filter_map(|k| {
            let v = es.folder_get(JOIN_FOLDER, &k).ok().flatten()?;
            let j: ForensicCorrelationJoinV2 = serde_json::from_value(v).ok()?;
            if j.agent_pid == api_pid {
                Some(j)
            } else {
                None
            }
        })
        .collect();
    out.sort_by_key(|j| j.issued_at_ms);
    out
}

/// Agents whose ComplianceContract (or activation hint) references this WitnessCtl session.
pub fn agents_for_witnessctl_session(state: &PlatformState, session_id: &str) -> Vec<String> {
    use crate::kernel::{agent_identity_envelope, compliance_contract};
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys(compliance_contract::COMPLIANCE_CONTRACT_FOLDER, None)
        .unwrap_or_default();
    let mut pids: Vec<String> = keys
        .into_iter()
        .filter_map(|k| {
            let v = es
                .folder_get(compliance_contract::COMPLIANCE_CONTRACT_FOLDER, &k)
                .ok()
                .flatten()?;
            let c: connector_trust::ComplianceContractV2 = serde_json::from_value(v).ok()?;
            if c.witnessctl_session_id.as_deref() == Some(session_id) {
                Some(c.agent_pid)
            } else {
                None
            }
        })
        .collect();
    let act_keys = es
        .folder_keys(agent_identity_envelope::ACTIVATION_FOLDER, None)
        .unwrap_or_default();
    for k in act_keys {
        if let Some(v) = es
            .folder_get(agent_identity_envelope::ACTIVATION_FOLDER, &k)
            .ok()
            .flatten()
        {
            if let Ok(a) = serde_json::from_value::<connector_trust::AgentActivationProfileV2>(v) {
                if a.witnessctl_session_hint.as_deref() == Some(session_id)
                    && !pids.contains(&a.agent_pid)
                {
                    pids.push(a.agent_pid);
                }
            }
        }
    }
    drop(es);
    pids.sort();
    pids.dedup();
    pids
}

/// Join payload for WitnessCtl export — contract digests + universal envelope IDs.
pub fn witnessctl_export_join(state: &PlatformState, session_id: &str) -> serde_json::Value {
    use crate::kernel::{agent_identity_envelope, compliance_contract};
    let agents = agents_for_witnessctl_session(state, session_id);
    let mut agent_joins = Vec::new();
    for pid in &agents {
        let contract = compliance_contract::load_compliance_contract(state, pid);
        let universals = agent_identity_envelope::list_forensic_universal(state, pid);
        let envelope_ids: Vec<String> = universals.iter().map(|u| u.envelope_id.clone()).collect();
        agent_joins.push(serde_json::json!({
            "agent_pid": pid,
            "compliance_contract_id": contract.as_ref().map(|c| &c.contract_id),
            "compliance_contract_digest_sha256": contract.as_ref().map(|c| &c.compliance_contract_digest_sha256),
            "identity_envelope_digest_sha256": contract.as_ref().map(|c| &c.identity_envelope_digest_sha256),
            "universal_envelope_ids": envelope_ids,
            "universal_envelope_count": universals.len(),
            "iia_chain_head": forensics::chain_head_for_agent(state, pid),
            "forensic_package": format!("GET /api/v1/forensics/package?agent_pid={pid}"),
        }));
    }
    serde_json::json!({
        "schema": "connector.witnessctl_iia_join.v2",
        "witnessctl_session_id": session_id,
        "agents": agent_joins,
        "honesty": "Platform IIA join — WitnessCtl remains SoT for framework evaluation; digests are court-tier when signing_tier=ed25519_court",
    })
}
