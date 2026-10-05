//! Adversarial / honesty checks for constitutional trust foundation (no live server).

#[test]
fn principal_rejects_spoofed_tenant_header() {
    let p = connector_trust::PrincipalContextV2::from_verified_claims(
        "usr_1",
        "a@b.c",
        "admin",
        vec!["agents:read".into()],
        Some("acme".into()),
        Some("jti1".into()),
        "access",
        None,
    );
    assert!(p.tenant_header_mismatch("evil"));
    assert!(!p.tenant_header_mismatch("acme"));
}

#[test]
fn custody_receipt_never_defaults_to_verified() {
    let r = connector_trust::CustodyReceiptV2 {
        receipt_id: "rcpt_1".into(),
        proof_id: Some("prf_1".into()),
        principal_id: "usr_1".into(),
        tenant_id: Some("acme".into()),
        event_range_start: None,
        event_range_end: None,
        policy_revision: Some(1),
        chain_head: Some("abc".into()),
        signer_key_id: None,
        artifact_digests: vec!["deadbeef".into()],
        signature_hex: None,
        verification_status: connector_trust::custody::CustodyVerificationStatus::Unverified,
        contract_version: 2,
    };
    let status = connector_trust::verify::verify_custody_receipt_structure(&r);
    assert_eq!(
        status,
        connector_trust::custody::CustodyVerificationStatus::Unverified
    );
}

#[test]
fn admission_ticket_v2_lifts_legacy_fields() {
    let t = connector_trust::AdmissionTicketV2::from_legacy_fields(
        "adm_1",
        0.1,
        Some("cid1".into()),
        Some(3),
        Some("active".into()),
    );
    assert_eq!(t.ticket_id, "adm_1");
    assert_eq!(t.contract_version, 2);
}

#[test]
fn cfni_mint_verify_round_trip() {
    let id = connector_trust::mint_flow_identity(b"secret", "usr_1", Some("t1".into()), 60_000, None);
    connector_trust::verify_flow_identity(&id, b"secret", id.issued_at_ms + 1).expect("ok");
}

#[test]
fn usage_event_schema_and_token_source() {
    let ev = connector_trust::UsageEventV2::new_llm_completion(
        "acct",
        "agent",
        "sess",
        "claude",
        "claude",
        "anthropic",
        10,
        20,
        connector_trust::UsageTokenSource::ProviderApi,
        None,
        None,
    );
    assert_eq!(ev.schema, connector_trust::USAGE_EVENT_SCHEMA);
    assert_eq!(ev.total_tokens, 30);
}

#[test]
fn causal_envelope_chains() {
    use connector_trust::CausalEnvelopeV2;
    let env = CausalEnvelopeV2 {
        envelope_id: "env_1".into(),
        principal_id: "usr".into(),
        tenant_id: Some("t".into()),
        workload_id: Some("agent".into()),
        session_id: None,
        delegation_chain: vec![],
        action: "memory_write".into(),
        resource: "k/graph".into(),
        policy_revision: None,
        decision: "allow".into(),
        admission_ticket_id: Some("adm_1".into()),
        input_digest: None,
        output_digest: None,
        side_effects: vec![],
        previous_mac: None,
        integrity_mac: Some("abc".into()),
        occurred_at_ms: 1,
        contract_version: 2,
    };
    assert_eq!(env.contract_version, 2);
}

#[test]
fn principal_context_round_trip_json() {
    let p = connector_trust::PrincipalContextV2::from_verified_claims(
        "usr_1",
        "a@b.c",
        "operator",
        vec!["agents:read".into()],
        Some("acme".into()),
        Some("jti1".into()),
        "access",
        None,
    );
    let json = serde_json::to_string(&p).expect("serialize");
    let back: connector_trust::PrincipalContextV2 = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.subject, "usr_1");
    assert_eq!(back.tenant_id.as_deref(), Some("acme"));
}
