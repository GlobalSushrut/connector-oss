//! Config tests — Part 1: Tier 1/2 (global, security, firewall, behavior, checkpoint, agent, pipeline)
//! Part 2 is in config_tests_ext.rs (tools, knowledge, RAG, policies, Tier 3, env-var errors)

#[cfg(test)]
mod config_tests_part1 {
    use crate::config::*;

    // ── Shared minimal fixture ────────────────────────────────────────────────
    const MINIMAL: &str = r#"
connector:
  provider: openai
  model: gpt-4o
  api_key: test-key
agents:
  bot:
    instructions: "You are helpful"
"#;

    // ── Shared full Tier-1/2 fixture ──────────────────────────────────────────
    const FULL_CORE: &str = r#"
connector:
  provider: openai
  model: gpt-4o
  api_key: sk-test
  endpoint: https://api.openai.com/v1
  max_tokens: 4096
  temperature: 0.7
  system_prompt: "You are a helpful assistant."
  storage: sqlite:./test.db
  comply: [hipaa, soc2, gdpr]
  fallbacks:
    - provider: anthropic
      model: claude-3-5-sonnet-20241022
      api_key: sk-ant-test
    - provider: deepseek
      model: deepseek-chat
      endpoint: https://api.deepseek.com/v1
  router:
    retry:
      max_retries: 5
      base_delay_ms: 200
      max_delay_ms: 10000
    circuit_breaker:
      failure_threshold: 3
      cooldown_secs: 60
  security:
    signing: true
    scitt: true
    key_rotation_days: 90
    data_classification: PHI
    jurisdiction: US
    retention_days: 2555
    require_mfa: true
    max_delegation_depth: 2
    ip_allowlist: ["10.0.0.0/8", "192.168.1.0/24"]
    audit_export: json
  firewall:
    preset: hipaa
    block_injection: true
    injection_threshold: 0.6
    pii_types: [ssn, credit_card, email, phone, dob, medical_record]
    pii_threshold: 0.7
    blocked_tools: [shell_exec, file_delete, network_raw]
    max_calls_per_minute: 30
    max_input_length: 8192
    weights:
      injection: 0.45
      pii: 0.30
      anomaly: 0.15
      policy_violation: 0.05
      rate_pressure: 0.03
      boundary_crossing: 0.02
    thresholds:
      warn: 0.3
      review: 0.6
      block: 0.8
  behavior:
    window_ms: 60000
    baseline_sample_size: 20
    anomaly_threshold: 2.0
    max_actions_per_window: 100
    max_tool_diversity: 15
    max_error_rate: 0.1
    max_data_volume: 10485760
    detect_contamination: true
  checkpoint:
    write_through: true
    wal_enabled: true
    auto_checkpoint_threshold: 50
agents:
  doctor:
    instructions: "You are a physician assistant."
    role: executor
    tools: [search_ehr, write_notes, order_lab, search_drugs]
    deny_tools: [delete_record, export_bulk]
    allow_data: [PHI, internal]
    deny_data: [financial, legal]
    require_approval: [order_lab, export_bulk]
    comply: [hipaa]
    rate_limit: 20
    budget:
      max_tokens: 100000
      max_cost_usd: 5.00
    output_guards:
      - name: no_pii_in_output
        pattern: "\\d{3}-\\d{2}-\\d{4}"
        negate: false
      - name: must_have_recommendation
        pattern: recommend
        negate: true
    security:
      data_classification: PHI
      retention_days: 2555
      signing: true
    llm:
      provider: anthropic
      model: claude-3-5-sonnet-20241022
      api_key: sk-ant-agent
  reviewer:
    instructions: "Review and approve actions."
    role: reviewer
    tools: [read_record]
    deny_data: [financial]
pipelines:
  triage:
    actors:
      - name: intake
        instructions: "Collect patient symptoms."
        tools: [read_form, search_ehr]
        deny_tools: [delete_record]
        allow_data: [PHI]
        deny_data: [financial]
      - name: diagnosis
        instructions: "Diagnose based on symptoms."
        tools: [search_ehr, search_drugs]
        memory_from: [intake]
      - name: treatment
        instructions: "Recommend treatment."
        tools: [write_notes, order_lab]
        require_approval: [order_lab]
        memory_from: [intake, diagnosis]
    flow: "intake -> diagnosis -> treatment"
    comply: [hipaa]
    hipaa:
      jurisdiction: US
      retention_days: 2555
    gdpr:
      retention_days: 1825
      dsar_enabled: true
    security:
      signing: true
      data_classification: PHI
    budget:
      max_tokens: 500000
      max_cost_usd: 20.00
    rate_limit: 10
memory:
  max_packets_per_agent: 10000
  eviction_policy: lru
  hot_tier_limit: 1000
  warm_tier_limit: 5000
  cold_tier_limit: 20000
  gc_interval_secs: 3600
  session_ttl_secs: 86400
  compression_enabled: true
  compression_threshold_tokens: 2000
  context_window_tokens: 128000
  seal_on_session_close: true
judgment:
  preset: medical
  decay_half_life_ms: 86400000.0
  min_operations: 5
  min_trust_gate: 60
  weights:
    cid_integrity: 1.2
    audit_coverage: 1.5
    access_control: 1.0
    evidence_quality: 1.8
    claim_coverage: 1.5
    temporal_freshness: 0.8
    contradiction_score: 1.5
    source_credibility: 1.0
"#;

    // ── 01. Minimal parses ────────────────────────────────────────────────────
    #[test]
    fn test_01_minimal_parses() {
        let cfg = load_config_str(MINIMAL).unwrap();
        assert_eq!(cfg.connector.provider.as_deref(), Some("openai"));
        assert_eq!(cfg.connector.model.as_deref(), Some("gpt-4o"));
        assert_eq!(cfg.connector.api_key.as_deref(), Some("test-key"));
        assert!(cfg.agents.contains_key("bot"));
        assert_eq!(cfg.agents["bot"].instructions, "You are helpful");
        // Tier 3 features all absent → all None
        assert!(cfg.cluster.is_none());
        assert!(cfg.swarm.is_none());
        assert!(cfg.streaming.is_none());
        assert!(cfg.mcp.is_none());
        assert!(cfg.server.is_none());
        assert!(cfg.perception.is_none());
        assert!(cfg.cognitive.is_none());
        assert!(cfg.tracing_config.is_none());
        assert!(cfg.observability.is_none());
    }

    // ── 02. LLM params ────────────────────────────────────────────────────────
    #[test]
    fn test_02_llm_params() {
        let g = &load_config_str(FULL_CORE).unwrap().connector;
        assert_eq!(g.provider.as_deref(), Some("openai"));
        assert_eq!(g.model.as_deref(), Some("gpt-4o"));
        assert_eq!(g.api_key.as_deref(), Some("sk-test"));
        assert_eq!(g.endpoint.as_deref(), Some("https://api.openai.com/v1"));
        assert_eq!(g.max_tokens, Some(4096));
        assert!((g.temperature.unwrap() - 0.7_f32).abs() < 1e-5);
        assert_eq!(g.system_prompt.as_deref(), Some("You are a helpful assistant."));
    }

    // ── 03. Fallbacks ─────────────────────────────────────────────────────────
    #[test]
    fn test_03_fallbacks() {
        let fb = &load_config_str(FULL_CORE).unwrap().connector.fallbacks;
        assert_eq!(fb.len(), 2);
        assert_eq!(fb[0].provider, "anthropic");
        assert_eq!(fb[0].model, "claude-3-5-sonnet-20241022");
        assert_eq!(fb[1].provider, "deepseek");
        assert_eq!(fb[1].endpoint.as_deref(), Some("https://api.deepseek.com/v1"));
    }

    // ── 04. Router ────────────────────────────────────────────────────────────
    #[test]
    fn test_04_router() {
        let router = load_config_str(FULL_CORE).unwrap().connector.router.unwrap();
        let retry = router.retry.unwrap();
        assert_eq!(retry.max_retries, Some(5));
        assert_eq!(retry.base_delay_ms, Some(200));
        assert_eq!(retry.max_delay_ms, Some(10000));
        let cb = router.circuit_breaker.unwrap();
        assert_eq!(cb.failure_threshold, Some(3));
        assert_eq!(cb.cooldown_secs, Some(60));
    }

    // ── 05. Storage ───────────────────────────────────────────────────────────
    #[test]
    fn test_05_storage() {
        assert_eq!(
            load_config_str(FULL_CORE).unwrap().connector.storage.as_deref(),
            Some("sqlite:./test.db")
        );
    }

    // ── 06. Comply list ───────────────────────────────────────────────────────
    #[test]
    fn test_06_comply_list() {
        let comply = &load_config_str(FULL_CORE).unwrap().connector.comply;
        assert!(comply.contains(&"hipaa".to_string()));
        assert!(comply.contains(&"soc2".to_string()));
        assert!(comply.contains(&"gdpr".to_string()));
    }

    // ── 07. Security — all 10 fields ──────────────────────────────────────────
    #[test]
    fn test_07_security_all_fields() {
        let sec = load_config_str(FULL_CORE).unwrap().connector.security.unwrap();
        assert_eq!(sec.signing, Some(true));
        assert_eq!(sec.scitt, Some(true));
        assert_eq!(sec.key_rotation_days, Some(90));
        assert_eq!(sec.data_classification.as_deref(), Some("PHI"));
        assert_eq!(sec.jurisdiction.as_deref(), Some("US"));
        assert_eq!(sec.retention_days, Some(2555));
        assert_eq!(sec.require_mfa, Some(true));
        assert_eq!(sec.max_delegation_depth, Some(2));
        assert_eq!(sec.ip_allowlist.len(), 2);
        assert!(sec.ip_allowlist.contains(&"10.0.0.0/8".to_string()));
        assert_eq!(sec.audit_export.as_deref(), Some("json"));
    }

    // ── 08. Firewall preset ───────────────────────────────────────────────────
    #[test]
    fn test_08_firewall_preset() {
        let fw = load_config_str(FULL_CORE).unwrap().connector.firewall.unwrap();
        assert_eq!(fw.preset.as_deref(), Some("hipaa"));
    }

    // ── 09. Firewall individual fields ────────────────────────────────────────
    #[test]
    fn test_09_firewall_fields() {
        let fw = load_config_str(FULL_CORE).unwrap().connector.firewall.unwrap();
        assert_eq!(fw.block_injection, Some(true));
        assert!((fw.injection_threshold.unwrap() - 0.6).abs() < 1e-9);
        assert_eq!(fw.pii_types.len(), 6);
        assert!(fw.pii_types.contains(&"ssn".to_string()));
        assert!(fw.pii_types.contains(&"medical_record".to_string()));
        assert!((fw.pii_threshold.unwrap() - 0.7).abs() < 1e-9);
        assert_eq!(fw.blocked_tools.len(), 3);
        assert!(fw.blocked_tools.contains(&"shell_exec".to_string()));
        assert_eq!(fw.max_calls_per_minute, Some(30));
        assert_eq!(fw.max_input_length, Some(8192));
    }

    // ── 10. Firewall signal weights (6 fields) ────────────────────────────────
    #[test]
    fn test_10_firewall_weights() {
        let w = load_config_str(FULL_CORE).unwrap().connector.firewall.unwrap().weights.unwrap();
        assert!((w.injection.unwrap() - 0.45).abs() < 1e-9);
        assert!((w.pii.unwrap() - 0.30).abs() < 1e-9);
        assert!((w.anomaly.unwrap() - 0.15).abs() < 1e-9);
        assert!((w.policy_violation.unwrap() - 0.05).abs() < 1e-9);
        assert!((w.rate_pressure.unwrap() - 0.03).abs() < 1e-9);
        assert!((w.boundary_crossing.unwrap() - 0.02).abs() < 1e-9);
    }

    // ── 11. Firewall verdict thresholds ───────────────────────────────────────
    #[test]
    fn test_11_firewall_thresholds() {
        let t = load_config_str(FULL_CORE).unwrap().connector.firewall.unwrap().thresholds.unwrap();
        assert!((t.warn.unwrap() - 0.3).abs() < 1e-9);
        assert!((t.review.unwrap() - 0.6).abs() < 1e-9);
        assert!((t.block.unwrap() - 0.8).abs() < 1e-9);
    }

    // ── 12. Behavior — all 8 fields ───────────────────────────────────────────
    #[test]
    fn test_12_behavior_all_fields() {
        let bh = load_config_str(FULL_CORE).unwrap().connector.behavior.unwrap();
        assert_eq!(bh.window_ms, Some(60000));
        assert_eq!(bh.baseline_sample_size, Some(20));
        assert!((bh.anomaly_threshold.unwrap() - 2.0).abs() < 1e-9);
        assert_eq!(bh.max_actions_per_window, Some(100));
        assert_eq!(bh.max_tool_diversity, Some(15));
        assert!((bh.max_error_rate.unwrap() - 0.1).abs() < 1e-9);
        assert_eq!(bh.max_data_volume, Some(10485760));
        assert_eq!(bh.detect_contamination, Some(true));
    }

    // ── 13. Checkpoint — all 3 fields ─────────────────────────────────────────
    #[test]
    fn test_13_checkpoint_all_fields() {
        let cp = load_config_str(FULL_CORE).unwrap().connector.checkpoint.unwrap();
        assert_eq!(cp.write_through, Some(true));
        assert_eq!(cp.wal_enabled, Some(true));
        assert_eq!(cp.auto_checkpoint_threshold, Some(50));
    }

    // ── 14. Agent basic fields ────────────────────────────────────────────────
    #[test]
    fn test_14_agent_basic() {
        let doc = load_config_str(FULL_CORE).unwrap().agents.remove("doctor").unwrap();
        assert_eq!(doc.instructions, "You are a physician assistant.");
        assert_eq!(doc.role.as_deref(), Some("executor"));
    }

    // ── 15. Agent ACL fields ──────────────────────────────────────────────────
    #[test]
    fn test_15_agent_acl() {
        let doc = load_config_str(FULL_CORE).unwrap().agents.remove("doctor").unwrap();
        assert_eq!(doc.tools.len(), 4);
        assert!(doc.tools.contains(&"order_lab".to_string()));
        assert!(doc.deny_tools.contains(&"delete_record".to_string()));
        assert!(doc.allow_data.contains(&"PHI".to_string()));
        assert!(doc.deny_data.contains(&"financial".to_string()));
        assert!(doc.require_approval.contains(&"order_lab".to_string()));
    }

    // ── 16. Agent comply / rate_limit / budget ────────────────────────────────
    #[test]
    fn test_16_agent_comply_budget() {
        let doc = load_config_str(FULL_CORE).unwrap().agents.remove("doctor").unwrap();
        assert_eq!(doc.comply, vec!["hipaa"]);
        assert_eq!(doc.rate_limit, Some(20));
        let b = doc.budget.unwrap();
        assert_eq!(b.max_tokens, Some(100000));
        assert!((b.max_cost_usd.unwrap() - 5.0).abs() < 1e-9);
    }

    // ── 17. Agent output_guards ───────────────────────────────────────────────
    #[test]
    fn test_17_agent_output_guards() {
        let guards = load_config_str(FULL_CORE).unwrap().agents.remove("doctor").unwrap().output_guards;
        assert_eq!(guards.len(), 2);
        assert_eq!(guards[0].name, "no_pii_in_output");
        assert!(!guards[0].negate);
        assert_eq!(guards[1].name, "must_have_recommendation");
        assert!(guards[1].negate);
    }

    // ── 18. Agent per-agent security override ─────────────────────────────────
    #[test]
    fn test_18_agent_security_override() {
        let sec = load_config_str(FULL_CORE).unwrap().agents.remove("doctor").unwrap().security.unwrap();
        assert_eq!(sec.data_classification.as_deref(), Some("PHI"));
        assert_eq!(sec.retention_days, Some(2555));
        assert_eq!(sec.signing, Some(true));
    }

    // ── 19. Agent per-agent LLM override ─────────────────────────────────────
    #[test]
    fn test_19_agent_llm_override() {
        let llm = load_config_str(FULL_CORE).unwrap().agents.remove("doctor").unwrap().llm.unwrap();
        assert_eq!(llm.provider, "anthropic");
        assert_eq!(llm.model, "claude-3-5-sonnet-20241022");
    }

    // ── 20. Pipeline actors + flow ────────────────────────────────────────────
    #[test]
    fn test_20_pipeline_actors_flow() {
        let triage = load_config_str(FULL_CORE).unwrap().pipelines.remove("triage").unwrap();
        assert_eq!(triage.actors.len(), 3);
        assert_eq!(triage.actors[0].name, "intake");
        assert_eq!(triage.actors[2].name, "treatment");
        assert_eq!(triage.flow.as_deref(), Some("intake -> diagnosis -> treatment"));
    }

    // ── 21. Pipeline memory_from ──────────────────────────────────────────────
    #[test]
    fn test_21_pipeline_memory_from() {
        let actors = load_config_str(FULL_CORE).unwrap().pipelines.remove("triage").unwrap().actors;
        assert!(actors[0].memory_from.is_empty());
        assert_eq!(actors[1].memory_from, vec!["intake"]);
        assert_eq!(actors[2].memory_from, vec!["intake", "diagnosis"]);
    }

    // ── 22. Pipeline comply / hipaa / gdpr ───────────────────────────────────
    #[test]
    fn test_22_pipeline_comply_hipaa_gdpr() {
        let triage = load_config_str(FULL_CORE).unwrap().pipelines.remove("triage").unwrap();
        assert_eq!(triage.comply, vec!["hipaa"]);
        let hipaa = triage.hipaa.unwrap();
        assert_eq!(hipaa.jurisdiction.as_deref(), Some("US"));
        assert_eq!(hipaa.retention_days, Some(2555));
        let gdpr = triage.gdpr.unwrap();
        assert_eq!(gdpr.retention_days, Some(1825));
        assert_eq!(gdpr.dsar_enabled, Some(true));
    }

    // ── 23. Pipeline security + budget ───────────────────────────────────────
    #[test]
    fn test_23_pipeline_security_budget() {
        let triage = load_config_str(FULL_CORE).unwrap().pipelines.remove("triage").unwrap();
        assert_eq!(triage.security.unwrap().signing, Some(true));
        let b = triage.budget.unwrap();
        assert_eq!(b.max_tokens, Some(500000));
        assert_eq!(triage.rate_limit, Some(10));
    }

    // ── 24. Memory management — all 11 fields ────────────────────────────────
    #[test]
    fn test_24_memory_management_all_fields() {
        let mem = load_config_str(FULL_CORE).unwrap().memory.unwrap();
        assert_eq!(mem.max_packets_per_agent, Some(10000));
        assert_eq!(mem.eviction_policy.as_deref(), Some("lru"));
        assert_eq!(mem.hot_tier_limit, Some(1000));
        assert_eq!(mem.warm_tier_limit, Some(5000));
        assert_eq!(mem.cold_tier_limit, Some(20000));
        assert_eq!(mem.gc_interval_secs, Some(3600));
        assert_eq!(mem.session_ttl_secs, Some(86400));
        assert!(mem.compression_enabled);
        assert_eq!(mem.compression_threshold_tokens, Some(2000));
        assert_eq!(mem.context_window_tokens, Some(128000));
        assert!(mem.seal_on_session_close);
    }

    // ── 25. Memory absent → None (Tier 2 omit = None) ────────────────────────
    #[test]
    fn test_25_memory_absent_is_none() {
        assert!(load_config_str(MINIMAL).unwrap().memory.is_none());
    }

    // ── 26. Judgment — all fields ─────────────────────────────────────────────
    #[test]
    fn test_26_judgment_all_fields() {
        let j = load_config_str(FULL_CORE).unwrap().judgment.unwrap();
        assert_eq!(j.preset.as_deref(), Some("medical"));
        assert!((j.decay_half_life_ms.unwrap() - 86400000.0).abs() < 1.0);
        assert_eq!(j.min_operations, Some(5));
        assert_eq!(j.min_trust_gate, Some(60));
        let w = j.weights.unwrap();
        assert!((w.cid_integrity.unwrap() - 1.2).abs() < 1e-9);
        assert!((w.audit_coverage.unwrap() - 1.5).abs() < 1e-9);
        assert!((w.evidence_quality.unwrap() - 1.8).abs() < 1e-9);
        assert!((w.contradiction_score.unwrap() - 1.5).abs() < 1e-9);
    }

    // ── 27. Judgment absent → None ────────────────────────────────────────────
    #[test]
    fn test_27_judgment_absent_is_none() {
        assert!(load_config_str(MINIMAL).unwrap().judgment.is_none());
    }

    // ── 28. Empty config — all defaults apply ─────────────────────────────────
    #[test]
    fn test_28_empty_config_defaults() {
        let cfg = load_config_str("{}").unwrap();
        assert!(cfg.connector.provider.is_none());
        assert!(cfg.agents.is_empty());
        assert!(cfg.pipelines.is_empty());
        assert!(cfg.tools.is_empty());
        assert!(cfg.policies.is_empty());
        assert!(cfg.knowledge.is_none());
        assert!(cfg.rag.is_none());
        assert!(cfg.cluster.is_none());
        assert!(cfg.swarm.is_none());
    }

    // ── 29. Multiple agents in one config ─────────────────────────────────────
    #[test]
    fn test_29_multiple_agents() {
        let agents = load_config_str(FULL_CORE).unwrap().agents;
        assert!(agents.contains_key("doctor"));
        assert!(agents.contains_key("reviewer"));
        assert_eq!(agents["reviewer"].role.as_deref(), Some("reviewer"));
    }

    // ── 30. Env-var interpolation — happy path ────────────────────────────────
    #[test]
    fn test_30_env_var_happy_path() {
        std::env::set_var("TEST_CFG_KEY_HAPPY", "sk-from-env-happy");
        let yaml = "connector:\n  api_key: ${TEST_CFG_KEY_HAPPY}\n";
        let cfg = load_config_str(yaml).unwrap();
        assert_eq!(cfg.connector.api_key.as_deref(), Some("sk-from-env-happy"));
        std::env::remove_var("TEST_CFG_KEY_HAPPY");
    }

    // ── 31. Env-var interpolation — missing var teaching error ────────────────
    #[test]
    fn test_31_env_var_missing_teaching_error() {
        std::env::remove_var("DEFINITELY_NOT_SET_XYZ_999");
        let yaml = "connector:\n  api_key: ${DEFINITELY_NOT_SET_XYZ_999}\n";
        let err = load_config_str(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("DEFINITELY_NOT_SET_XYZ_999"), "should name the var: {msg}");
        assert!(msg.contains("export"), "should show fix command: {msg}");
    }

    // ── 32. Env-var interpolation — multiple missing collected together ────────
    #[test]
    fn test_32_env_var_multiple_missing() {
        std::env::remove_var("MISSING_VAR_A_999");
        std::env::remove_var("MISSING_VAR_B_999");
        let yaml = "connector:\n  api_key: ${MISSING_VAR_A_999}\n  endpoint: ${MISSING_VAR_B_999}\n";
        let err = load_config_str(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("MISSING_VAR_A_999"), "should list var A: {msg}");
        assert!(msg.contains("MISSING_VAR_B_999"), "should list var B: {msg}");
    }

    // ── 33. Env-var interpolation — duplicate var reported once ───────────────
    #[test]
    fn test_33_env_var_duplicate_reported_once() {
        std::env::remove_var("DUPE_VAR_999");
        let yaml = "connector:\n  api_key: ${DUPE_VAR_999}\n  endpoint: ${DUPE_VAR_999}\n";
        let err = load_config_str(yaml).unwrap_err();
        let msg = err.to_string();
        let count = msg.matches("DUPE_VAR_999").count();
        assert!(count <= 2, "duplicate var should not be listed many times: {msg}");
    }

    // ── 34. Parse error — bad YAML ────────────────────────────────────────────
    #[test]
    fn test_34_parse_error_bad_yaml() {
        let yaml = "connector:\n  provider: [unclosed bracket\n";
        let err = load_config_str(yaml).unwrap_err();
        assert!(matches!(err, ConfigError::ParseError(_)));
        let msg = err.to_string();
        assert!(msg.contains("YAML") || msg.contains("parse") || msg.contains("syntax") || msg.len() > 10);
    }

    // ── 35. File not found error ──────────────────────────────────────────────
    #[test]
    fn test_35_file_not_found_error() {
        let err = load_config("/tmp/definitely_does_not_exist_connector_xyz.yaml").unwrap_err();
        assert!(matches!(err, ConfigError::FileNotFound { .. }));
        let msg = err.to_string();
        assert!(msg.contains("connector.yaml") || msg.contains("CONNECTOR_CONFIG") || msg.contains("not found"));
    }
}
