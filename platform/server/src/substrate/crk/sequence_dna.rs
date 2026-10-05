//! Memory Sequence DNA — mint / cue var digests / type pairing helpers.

use connector_trust::{
    ActionCueEnvelope, MemoryDnaType, MemoryRelationKind, MemorySequenceDnaV1,
    relation_type_pairing_ok,
};

use super::digest_hex;

/// Cue binding sequence for var_digest slot.
pub fn cue_var_digest(cue: &ActionCueEnvelope) -> String {
    digest_hex(
        format!(
            "{}|{}|{}|{}|{}",
            cue.agent_pid,
            cue.action_digest,
            cue.phase,
            cue.bound_skill.as_deref().unwrap_or(""),
            cue.risk
        )
        .as_bytes(),
    )
}

pub fn mint_node_dna(
    agent_pid: &str,
    type_dna: MemoryDnaType,
    cid: &str,
    data_bytes: &[u8],
    var_digest: &str,
    index_key: &str,
    auth_root: &str,
) -> MemorySequenceDnaV1 {
    MemorySequenceDnaV1::mint(
        agent_pid,
        type_dna,
        cid,
        digest_hex(data_bytes),
        var_digest,
        index_key,
        auth_root,
    )
}

pub fn edge_types_ok(
    kind: MemoryRelationKind,
    from: MemoryDnaType,
    to: MemoryDnaType,
) -> bool {
    relation_type_pairing_ok(kind, from, to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::ACTION_CUE_SCHEMA;

    #[test]
    fn digest_stable_and_verifies() {
        let d = MemorySequenceDnaV1::mint(
            "agent:1",
            MemoryDnaType::State,
            "cid:1",
            "data",
            "var",
            "idx",
            "root",
        );
        assert!(d.verify_digest());
        assert_eq!(d.sequence_digest.len(), 64);
    }

    #[test]
    fn procedure_requires_state_ok() {
        assert!(edge_types_ok(
            MemoryRelationKind::Requires,
            MemoryDnaType::Procedure,
            MemoryDnaType::State
        ));
        assert!(!edge_types_ok(
            MemoryRelationKind::Requires,
            MemoryDnaType::State,
            MemoryDnaType::Procedure
        ));
    }

    #[test]
    fn cue_var_changes_with_action() {
        let a = ActionCueEnvelope {
            schema: ACTION_CUE_SCHEMA.into(),
            agent_pid: "a".into(),
            generation: 1,
            bound_skill: None,
            phase: "recall".into(),
            action_digest: "x".into(),
            risk: "low".into(),
            token_budget: 1,
            max_range_cover: 4,
        };
        let mut b = a.clone();
        b.action_digest = "y".into();
        assert_ne!(cue_var_digest(&a), cue_var_digest(&b));
    }
}
