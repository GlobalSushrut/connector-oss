//! EngineStore-backed CRK harness — supersession, commit mismatch, stability.
//! Tests run without full PlatformState by driving EngineStore folders directly.

#[cfg(test)]
mod tests {
    use connector_engine::engine_store::{EngineStore, InMemoryEngineStore};
    use connector_trust::{
        MemoryEnvelope, StateClaim, TrustTier, MEMORY_ENVELOPE_SCHEMA, STATE_CLAIM_SCHEMA,
    };
    use serde_json::json;

    use super::super::{digest_hex, FOLDER_CLAIMS, FOLDER_COMMITS, FOLDER_ROOTS};

    fn put_claim_raw(
        es: &mut dyn EngineStore,
        agent_pid: &str,
        claim_id: &str,
        subject: &str,
        predicate: &str,
        value: serde_json::Value,
        trust: TrustTier,
        active: bool,
        supersedes: Option<&str>,
        valid_until: Option<i64>,
    ) {
        let env = MemoryEnvelope {
            schema: MEMORY_ENVELOPE_SCHEMA.into(),
            cid: claim_id.into(),
            agent_pid: agent_pid.into(),
            origin: "harness".into(),
            origin_authority: trust,
            created_at_ms: 1,
            observed_at_ms: 1,
            verification_state: "committed".into(),
            evidence_cids: vec![],
            world_scope: None,
            skill_scope: None,
            valid_from_ms: Some(1),
            valid_until_ms: valid_until,
            lineage_digest: digest_hex(claim_id.as_bytes()),
        };
        let claim = StateClaim {
            schema: STATE_CLAIM_SCHEMA.into(),
            claim_id: claim_id.into(),
            agent_pid: agent_pid.into(),
            subject: subject.into(),
            predicate: predicate.into(),
            value,
            valid_from_ms: 1,
            valid_until_ms: valid_until,
            observed_at_ms: 1,
            source: "harness".into(),
            supersedes: supersedes.map(|s| s.to_string()),
            confidence: 0.9,
            evidence_cids: vec![],
            envelope: env,
            active,
        };
        let key = format!("{agent_pid}:{claim_id}");
        es.folder_put(FOLDER_CLAIMS, &key, &serde_json::to_value(&claim).unwrap())
            .unwrap();
        if active {
            es.folder_put(
                FOLDER_CLAIMS,
                &format!("current:{agent_pid}:{subject}:{predicate}"),
                &json!({ "claim_id": claim_id }),
            )
            .unwrap();
        }
    }

    #[test]
    fn supersession_keeps_old_historical() {
        let mut es = InMemoryEngineStore::new();
        put_claim_raw(
            &mut es,
            "a1",
            "c_old",
            "door",
            "locked",
            json!(true),
            TrustTier::T2SourceBound,
            false,
            None,
            Some(100),
        );
        put_claim_raw(
            &mut es,
            "a1",
            "c_new",
            "door",
            "locked",
            json!(false),
            TrustTier::T3EnvVerified,
            true,
            Some("c_old"),
            None,
        );
        let old: StateClaim = serde_json::from_value(
            es.folder_get(FOLDER_CLAIMS, "a1:c_old")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let new: StateClaim = serde_json::from_value(
            es.folder_get(FOLDER_CLAIMS, "a1:c_new")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(!old.active);
        assert!(old.valid_until_ms.is_some());
        assert!(old.was_valid_at(50)); // historically true in window
        assert!(!old.was_valid_at(150));
        assert!(!old.is_active_at(50)); // inactive → not for cognition
        assert!(new.active);
        assert!(new.is_active_at(200));
        let cur = es
            .folder_get(FOLDER_CLAIMS, "current:a1:door:locked")
            .unwrap()
            .unwrap();
        assert_eq!(cur["claim_id"], "c_new");
    }

    #[test]
    fn commit_root_mismatch_is_detectable() {
        let mut es = InMemoryEngineStore::new();
        es.folder_put(
            FOLDER_ROOTS,
            "a1",
            &json!({ "root": "root_aaa", "commit_id": "mc_1" }),
        )
        .unwrap();
        let live = es
            .folder_get(FOLDER_ROOTS, "a1")
            .unwrap()
            .unwrap()
            .get("root")
            .and_then(|r| r.as_str())
            .unwrap()
            .to_string();
        assert!(super::super::memory_commit::root_mismatch("root_bbb", &live));
        assert!(!super::super::memory_commit::root_mismatch("root_aaa", &live));
    }

    #[test]
    fn claim_prefix_scan_excludes_current_pointers() {
        let mut es = InMemoryEngineStore::new();
        put_claim_raw(
            &mut es,
            "a1",
            "c1",
            "x",
            "y",
            json!(1),
            TrustTier::T1Observed,
            true,
            None,
            None,
        );
        let keys = es.folder_keys(FOLDER_CLAIMS, Some("a1:")).unwrap();
        assert!(keys.iter().any(|k| k == "a1:c1"));
        assert!(!keys.iter().any(|k| k.starts_with("current:")));
        let _ = FOLDER_COMMITS;
    }

    #[test]
    fn trust_floor_blocks_poison_rank() {
        assert!(TrustTier::T0External.rank() < TrustTier::T3EnvVerified.rank());
        assert!(TrustTier::promotion_violation(
            TrustTier::T0External,
            TrustTier::T3EnvVerified
        ));
    }
}
