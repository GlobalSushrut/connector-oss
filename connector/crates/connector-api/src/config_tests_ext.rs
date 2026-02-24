//! Config tests — Part 2a: Tools, Knowledge, RAG, Policies, Cluster, Swarm, Streaming, MCP
//! Part 2b continues in the second half of this file (tests 21-40).

#[cfg(test)]
mod config_tests_part2 {
    use crate::config::*;

    // ── Shared fixture for Tier 2 extended + Tier 3 ───────────────────────────
    const EXT: &str = r#"
connector:
  provider: openai
  model: gpt-4o
  api_key: sk-test
tools:
  search_ehr:
    description: "Search electronic health records"
    resource: "ehr://patients/*"
    actions: [read]
    data_classification: PHI
    requires_approval: false
    timeout_ms: 5000
    blocked: false
  order_lab:
    description: "Order a laboratory test"
    resource: "ehr://orders/*"
    actions: [write, execute]
    data_classification: PHI
    requires_approval: true
    timeout_ms: 10000
  shell_exec:
    description: "Execute shell command"
    resource: "system://shell"
    actions: [execute]
    blocked: true
knowledge:
  seed:
    entities:
      - id: aspirin
        type: drug
        tags: [analgesic, nsaid, antiplatelet]
        attrs:
          generic_name: acetylsalicylic acid
          half_life_hours: 3.5
      - id: ibuprofen
        type: drug
        tags: [analgesic, nsaid]
    edges:
      - from: aspirin
        to: ibuprofen
        relation: similar_to
        weight: 0.85
      - from: aspirin
        to: penicillin_allergy
        relation: unrelated_to
        weight: 0.0
  inject:
    - source: file:./data/drugs.json
      format: json
      entity_type: drug
      id_field: drug_id
      tag_fields: [category, name, class]
      refresh_interval_hours: 0
    - source: https://api.example.com/formulary
      format: jsonl
      entity_type: formulary_drug
      id_field: ndc_code
      tag_fields: [drug_name, tier]
      auth_header: Bearer sk-formulary
      refresh_interval_hours: 24
  grounding:
    - source: file:./data/grounding.json
      format: json
  compile_on_startup: true
  max_compiled_summaries: 100
  contradiction_check: true
rag:
  enabled: true
  budget: 4096
  max_facts: 20
  min_relevance: 0.3
  strategy: hybrid
  namespaces: [medical, drugs]
  sources: [knowledge_graph, memory, shared_memory]
policies:
  hipaa_minimum:
    name: HIPAA Minimum Necessary
    enabled: true
    rules:
      - effect: deny
        action_pattern: "export.*"
        resource_pattern: "patient.*"
        roles: [intern, viewer]
        priority: 100
      - effect: require_approval
        action_pattern: "delete.*"
        roles: []
        priority: 90
  open_access:
    name: Open Access
    enabled: false
    rules:
      - effect: allow
        action_pattern: "*"
        priority: 1
cluster:
  mode: cluster
  node_id: node-1
  peers: ["node2:7000", "node3:7000"]
  replication_factor: 2
  consensus: raft
  partition_strategy: consistent_hash
  max_nodes: 10
  heartbeat_interval_ms: 500
  election_timeout_ms: 3000
  replication_bus: nats://localhost:4222
  scitt_federation: true
swarm:
  max_concurrent_agents: 50
  agent_pool_size: 10
  spawn_strategy: pre_warm
  handoff_timeout_ms: 5000
  a2a_enabled: true
  a2a_protocol: bus
  max_delegation_hops: 3
  load_balance: true
  load_balance_strategy: least_loaded
  saga_rollback: true
  max_pipeline_steps: 20
streaming:
  protocol: sse
  chunk_size_tokens: 10
  heartbeat_interval_ms: 1000
  max_connections: 100
  buffer_chunks: 50
  include_audit_events: true
  include_trust_updates: true
mcp:
  mode: both
  server_port: 8090
  server_host: 127.0.0.1
  client_endpoints: ["http://mcp-server-1:8090", "http://mcp-server-2:8090"]
  tool_discovery: auto
  auth_token: mcp-secret
  resource_subscriptions: true
  max_sessions: 50
  session_timeout_secs: 3600
server:
  host: 0.0.0.0
  port: 8080
  cors_origins: ["https://app.example.com", "https://admin.example.com"]
  request_timeout_secs: 30
  max_request_size_bytes: 1048576
  metrics_enabled: true
  health_enabled: true
  api_key: srv-secret
  rate_limit_rps: 100
  tls:
    cert_file: /etc/ssl/cert.pem
    key_file: /etc/ssl/key.pem
    min_version: "1.3"
perception:
  extract_entities: true
  extract_claims: true
  verify_claims: true
  max_entities: 50
  quality_threshold: 60
  block_low_quality: true
  grounding_domain: medical
  strict_grounding: false
cognitive:
  max_cycles: 5
  reflection_enabled: true
  compile_knowledge_after_cycle: true
  contradiction_halt: true
  chain_of_thought: true
  max_reasoning_steps: 10
  min_cycle_quality: 50
tracing_config:
  otel_format: true
  include_kernel_spans: false
  include_llm_spans: true
  include_tool_spans: true
  max_spans_per_trace: 1000
  sampling_rate: 1.0
  otel_endpoint: http://otel-collector:4317
  otel_protocol: grpc
observability:
  service_name: connector-prod
  service_version: 1.0.0
  environment: production
  otel_endpoint: http://otel-collector:4317
  otel_protocol: grpc
  trace_sampling_rate: 0.1
  metrics_enabled: true
  metrics_interval_secs: 15
  log_level: info
  log_format: json
  log_export: true
  resource_attrs:
    team: platform
    region: us-east-1
"#;

    // ── 01. Tool — all 7 fields ───────────────────────────────────────────────
    #[test]
    fn test_01_tool_all_fields() {
        let mut tools = load_config_str(EXT).unwrap().tools;
        let ehr = tools.remove("search_ehr").unwrap();
        assert_eq!(ehr.description, "Search electronic health records");
        assert_eq!(ehr.resource.as_deref(), Some("ehr://patients/*"));
        assert_eq!(ehr.actions, vec!["read"]);
        assert_eq!(ehr.data_classification.as_deref(), Some("PHI"));
        assert!(!ehr.requires_approval);
        assert_eq!(ehr.timeout_ms, Some(5000));
        assert!(!ehr.blocked);
    }

    // ── 02. Tool requires_approval + multi-action ─────────────────────────────
    #[test]
    fn test_02_tool_requires_approval() {
        let lab = load_config_str(EXT).unwrap().tools.remove("order_lab").unwrap();
        assert!(lab.requires_approval);
        assert_eq!(lab.actions, vec!["write", "execute"]);
        assert_eq!(lab.timeout_ms, Some(10000));
    }

    // ── 03. Tool blocked flag ─────────────────────────────────────────────────
    #[test]
    fn test_03_tool_blocked_flag() {
        let shell = load_config_str(EXT).unwrap().tools.remove("shell_exec").unwrap();
        assert!(shell.blocked);
        assert_eq!(shell.resource.as_deref(), Some("system://shell"));
    }

    // ── 04. Knowledge seed entities ───────────────────────────────────────────
    #[test]
    fn test_04_knowledge_seed_entities() {
        let seed = load_config_str(EXT).unwrap().knowledge.unwrap().seed.unwrap();
        assert_eq!(seed.entities.len(), 2);
        let asp = &seed.entities[0];
        assert_eq!(asp.id, "aspirin");
        assert_eq!(asp.entity_type.as_deref(), Some("drug"));
        assert!(asp.tags.contains(&"antiplatelet".to_string()));
        assert_eq!(asp.attrs["generic_name"].as_str().unwrap(), "acetylsalicylic acid");
        assert!((asp.attrs["half_life_hours"].as_f64().unwrap() - 3.5).abs() < 1e-9);
    }

    // ── 05. Knowledge seed edges ──────────────────────────────────────────────
    #[test]
    fn test_05_knowledge_seed_edges() {
        let seed = load_config_str(EXT).unwrap().knowledge.unwrap().seed.unwrap();
        assert_eq!(seed.edges.len(), 2);
        assert_eq!(seed.edges[0].from, "aspirin");
        assert_eq!(seed.edges[0].to, "ibuprofen");
        assert_eq!(seed.edges[0].relation, "similar_to");
        assert!((seed.edges[0].weight - 0.85).abs() < 1e-9);
        assert!((seed.edges[1].weight - 0.0).abs() < 1e-9);
    }

    // ── 06. Knowledge inject — all 7 fields ───────────────────────────────────
    #[test]
    fn test_06_knowledge_inject_all_fields() {
        let inject = load_config_str(EXT).unwrap().knowledge.unwrap().inject;
        assert_eq!(inject.len(), 2);
        let f = &inject[0];
        assert_eq!(f.source, "file:./data/drugs.json");
        assert_eq!(f.format, "json");
        assert_eq!(f.entity_type.as_deref(), Some("drug"));
        assert_eq!(f.id_field.as_deref(), Some("drug_id"));
        assert_eq!(f.tag_fields.len(), 3);
        assert!(f.tag_fields.contains(&"category".to_string()));
        assert_eq!(f.refresh_interval_hours, Some(0));
        let h = &inject[1];
        assert_eq!(h.format, "jsonl");
        assert_eq!(h.auth_header.as_deref(), Some("Bearer sk-formulary"));
        assert_eq!(h.refresh_interval_hours, Some(24));
    }

    // ── 07. Knowledge grounding ───────────────────────────────────────────────
    #[test]
    fn test_07_knowledge_grounding() {
        let g = load_config_str(EXT).unwrap().knowledge.unwrap().grounding;
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].source, "file:./data/grounding.json");
        assert_eq!(g[0].format, "json");
    }

    // ── 08. Knowledge compile + contradiction flags ───────────────────────────
    #[test]
    fn test_08_knowledge_compile_flags() {
        let k = load_config_str(EXT).unwrap().knowledge.unwrap();
        assert!(k.compile_on_startup);
        assert_eq!(k.max_compiled_summaries, Some(100));
        assert!(k.contradiction_check);
    }

    // ── 09. RAG — all 7 fields ────────────────────────────────────────────────
    #[test]
    fn test_09_rag_all_fields() {
        let rag = load_config_str(EXT).unwrap().rag.unwrap();
        assert!(rag.enabled);
        assert_eq!(rag.budget, Some(4096));
        assert_eq!(rag.max_facts, Some(20));
        assert!((rag.min_relevance.unwrap() - 0.3).abs() < 1e-9);
        assert_eq!(rag.strategy.as_deref(), Some("hybrid"));
        assert_eq!(rag.namespaces, vec!["medical", "drugs"]);
        assert_eq!(rag.sources, vec!["knowledge_graph", "memory", "shared_memory"]);
    }

    // ── 10. Policies — rules all fields ──────────────────────────────────────
    #[test]
    fn test_10_policies_rules() {
        let mut policies = load_config_str(EXT).unwrap().policies;
        let hipaa = policies.remove("hipaa_minimum").unwrap();
        assert_eq!(hipaa.name, "HIPAA Minimum Necessary");
        assert!(hipaa.enabled);
        assert_eq!(hipaa.rules.len(), 2);
        let r0 = &hipaa.rules[0];
        assert_eq!(r0.effect, "deny");
        assert_eq!(r0.action_pattern, "export.*");
        assert_eq!(r0.resource_pattern.as_deref(), Some("patient.*"));
        assert_eq!(r0.roles, vec!["intern", "viewer"]);
        assert_eq!(r0.priority, 100);
        let r1 = &hipaa.rules[1];
        assert_eq!(r1.effect, "require_approval");
        assert_eq!(r1.priority, 90);
        let open = policies.remove("open_access").unwrap();
        assert!(!open.enabled);
    }

    // ── 11. Cluster — all 11 fields ───────────────────────────────────────────
    #[test]
    fn test_11_cluster_all_fields() {
        let c = load_config_str(EXT).unwrap().cluster.unwrap();
        assert_eq!(c.mode, "cluster");
        assert_eq!(c.node_id.as_deref(), Some("node-1"));
        assert_eq!(c.peers.len(), 2);
        assert!(c.peers.contains(&"node2:7000".to_string()));
        assert_eq!(c.replication_factor, Some(2));
        assert_eq!(c.consensus.as_deref(), Some("raft"));
        assert_eq!(c.partition_strategy.as_deref(), Some("consistent_hash"));
        assert_eq!(c.max_nodes, Some(10));
        assert_eq!(c.heartbeat_interval_ms, Some(500));
        assert_eq!(c.election_timeout_ms, Some(3000));
        assert_eq!(c.replication_bus.as_deref(), Some("nats://localhost:4222"));
        assert!(c.scitt_federation);
    }

    // ── 12. Cluster absent → None (Tier 3 revoke) ────────────────────────────
    #[test]
    fn test_12_cluster_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.cluster.is_none());
    }

    // ── 13. Swarm — all 11 fields ─────────────────────────────────────────────
    #[test]
    fn test_13_swarm_all_fields() {
        let s = load_config_str(EXT).unwrap().swarm.unwrap();
        assert_eq!(s.max_concurrent_agents, Some(50));
        assert_eq!(s.agent_pool_size, Some(10));
        assert_eq!(s.spawn_strategy.as_deref(), Some("pre_warm"));
        assert_eq!(s.handoff_timeout_ms, Some(5000));
        assert!(s.a2a_enabled);
        assert_eq!(s.a2a_protocol.as_deref(), Some("bus"));
        assert_eq!(s.max_delegation_hops, Some(3));
        assert!(s.load_balance);
        assert_eq!(s.load_balance_strategy.as_deref(), Some("least_loaded"));
        assert!(s.saga_rollback);
        assert_eq!(s.max_pipeline_steps, Some(20));
    }

    // ── 14. Swarm absent → None (Tier 3 revoke) ──────────────────────────────
    #[test]
    fn test_14_swarm_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.swarm.is_none());
    }

    // ── 15. Streaming — all 7 fields ─────────────────────────────────────────
    #[test]
    fn test_15_streaming_all_fields() {
        let s = load_config_str(EXT).unwrap().streaming.unwrap();
        assert_eq!(s.protocol, "sse");
        assert_eq!(s.chunk_size_tokens, Some(10));
        assert_eq!(s.heartbeat_interval_ms, Some(1000));
        assert_eq!(s.max_connections, Some(100));
        assert_eq!(s.buffer_chunks, Some(50));
        assert!(s.include_audit_events);
        assert!(s.include_trust_updates);
    }

    // ── 16. Streaming absent → None (Tier 3 revoke) ──────────────────────────
    #[test]
    fn test_16_streaming_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.streaming.is_none());
    }

    // ── 17. MCP — all 9 fields ────────────────────────────────────────────────
    #[test]
    fn test_17_mcp_all_fields() {
        let m = load_config_str(EXT).unwrap().mcp.unwrap();
        assert_eq!(m.mode, "both");
        assert_eq!(m.server_port, Some(8090));
        assert_eq!(m.server_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(m.client_endpoints.len(), 2);
        assert!(m.client_endpoints.contains(&"http://mcp-server-1:8090".to_string()));
        assert_eq!(m.tool_discovery.as_deref(), Some("auto"));
        assert_eq!(m.auth_token.as_deref(), Some("mcp-secret"));
        assert!(m.resource_subscriptions);
        assert_eq!(m.max_sessions, Some(50));
        assert_eq!(m.session_timeout_secs, Some(3600));
    }

    // ── 18. MCP absent → None (Tier 3 revoke) ────────────────────────────────
    #[test]
    fn test_18_mcp_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.mcp.is_none());
    }

    // ── 19. Multiple tools in one config ──────────────────────────────────────
    #[test]
    fn test_19_multiple_tools() {
        let tools = load_config_str(EXT).unwrap().tools;
        assert_eq!(tools.len(), 3);
        assert!(tools.contains_key("search_ehr"));
        assert!(tools.contains_key("order_lab"));
        assert!(tools.contains_key("shell_exec"));
    }

    // ── 20. Multiple policies in one config ───────────────────────────────────
    #[test]
    fn test_20_multiple_policies() {
        let policies = load_config_str(EXT).unwrap().policies;
        assert_eq!(policies.len(), 2);
        assert!(policies.contains_key("hipaa_minimum"));
        assert!(policies.contains_key("open_access"));
    }

    // ── 21. Server — all fields including TLS ────────────────────────────────
    #[test]
    fn test_21_server_all_fields() {
        let srv = load_config_str(EXT).unwrap().server.unwrap();
        assert_eq!(srv.host.as_deref(), Some("0.0.0.0"));
        assert_eq!(srv.port, Some(8080));
        assert_eq!(srv.cors_origins.len(), 2);
        assert!(srv.cors_origins.contains(&"https://app.example.com".to_string()));
        assert_eq!(srv.request_timeout_secs, Some(30));
        assert_eq!(srv.max_request_size_bytes, Some(1048576));
        assert!(srv.metrics_enabled);
        assert!(srv.health_enabled);
        assert_eq!(srv.api_key.as_deref(), Some("srv-secret"));
        assert_eq!(srv.rate_limit_rps, Some(100));
        let tls = srv.tls.unwrap();
        assert_eq!(tls.cert_file, "/etc/ssl/cert.pem");
        assert_eq!(tls.key_file, "/etc/ssl/key.pem");
        assert_eq!(tls.min_version.as_deref(), Some("1.3"));
    }

    // ── 22. Server absent → None (Tier 3 revoke) ─────────────────────────────
    #[test]
    fn test_22_server_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.server.is_none());
    }

    // ── 23. Server without TLS — tls field is None ───────────────────────────
    #[test]
    fn test_23_server_without_tls() {
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\nserver:\n  port: 9090\n";
        let srv = load_config_str(yaml).unwrap().server.unwrap();
        assert_eq!(srv.port, Some(9090));
        assert!(srv.tls.is_none());
    }

    // ── 24. Perception — all 8 fields ────────────────────────────────────────
    #[test]
    fn test_24_perception_all_fields() {
        let p = load_config_str(EXT).unwrap().perception.unwrap();
        assert!(p.extract_entities);
        assert!(p.extract_claims);
        assert!(p.verify_claims);
        assert_eq!(p.max_entities, Some(50));
        assert_eq!(p.quality_threshold, Some(60));
        assert!(p.block_low_quality);
        assert_eq!(p.grounding_domain.as_deref(), Some("medical"));
        assert!(!p.strict_grounding);
    }

    // ── 25. Perception absent → None (Tier 3 revoke) ─────────────────────────
    #[test]
    fn test_25_perception_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.perception.is_none());
    }

    // ── 26. Cognitive — all 7 fields ─────────────────────────────────────────
    #[test]
    fn test_26_cognitive_all_fields() {
        let cog = load_config_str(EXT).unwrap().cognitive.unwrap();
        assert_eq!(cog.max_cycles, Some(5));
        assert!(cog.reflection_enabled);
        assert!(cog.compile_knowledge_after_cycle);
        assert!(cog.contradiction_halt);
        assert!(cog.chain_of_thought);
        assert_eq!(cog.max_reasoning_steps, Some(10));
        assert_eq!(cog.min_cycle_quality, Some(50));
    }

    // ── 27. Cognitive absent → None (Tier 3 revoke) ──────────────────────────
    #[test]
    fn test_27_cognitive_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.cognitive.is_none());
    }

    // ── 28. Tracing — all 8 fields ───────────────────────────────────────────
    #[test]
    fn test_28_tracing_all_fields() {
        let t = load_config_str(EXT).unwrap().tracing_config.unwrap();
        assert!(t.otel_format);
        assert!(!t.include_kernel_spans);
        assert!(t.include_llm_spans);
        assert!(t.include_tool_spans);
        assert_eq!(t.max_spans_per_trace, Some(1000));
        assert!((t.sampling_rate.unwrap() - 1.0).abs() < 1e-9);
        assert_eq!(t.otel_endpoint.as_deref(), Some("http://otel-collector:4317"));
        assert_eq!(t.otel_protocol.as_deref(), Some("grpc"));
    }

    // ── 29. Tracing absent → None (Tier 3 revoke) ────────────────────────────
    #[test]
    fn test_29_tracing_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.tracing_config.is_none());
    }

    // ── 30. Observability — all 12 fields ────────────────────────────────────
    #[test]
    fn test_30_observability_all_fields() {
        let obs = load_config_str(EXT).unwrap().observability.unwrap();
        assert_eq!(obs.service_name.as_deref(), Some("connector-prod"));
        assert_eq!(obs.service_version.as_deref(), Some("1.0.0"));
        assert_eq!(obs.environment.as_deref(), Some("production"));
        assert_eq!(obs.otel_endpoint.as_deref(), Some("http://otel-collector:4317"));
        assert_eq!(obs.otel_protocol.as_deref(), Some("grpc"));
        assert!((obs.trace_sampling_rate.unwrap() - 0.1).abs() < 1e-9);
        assert!(obs.metrics_enabled);
        assert_eq!(obs.metrics_interval_secs, Some(15));
        assert_eq!(obs.log_level.as_deref(), Some("info"));
        assert_eq!(obs.log_format.as_deref(), Some("json"));
        assert!(obs.log_export);
        assert_eq!(obs.resource_attrs.get("team").map(|s| s.as_str()), Some("platform"));
        assert_eq!(obs.resource_attrs.get("region").map(|s| s.as_str()), Some("us-east-1"));
    }

    // ── 31. Observability absent → None (Tier 3 revoke) ──────────────────────
    #[test]
    fn test_31_observability_absent_is_none() {
        let cfg = load_config_str("connector:\n  provider: openai\n  model: gpt-4o\n").unwrap();
        assert!(cfg.observability.is_none());
    }

    // ── 32. All 9 Tier 3 sections present in EXT fixture ─────────────────────
    #[test]
    fn test_32_all_tier3_sections_present() {
        let cfg = load_config_str(EXT).unwrap();
        assert!(cfg.cluster.is_some());
        assert!(cfg.swarm.is_some());
        assert!(cfg.streaming.is_some());
        assert!(cfg.mcp.is_some());
        assert!(cfg.server.is_some());
        assert!(cfg.perception.is_some());
        assert!(cfg.cognitive.is_some());
        assert!(cfg.tracing_config.is_some());
        assert!(cfg.observability.is_some());
    }

    // ── 33. Tier 3 selective — only streaming, all others None ───────────────
    #[test]
    fn test_33_tier3_selective_streaming_only() {
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\nstreaming:\n  protocol: websocket\n  chunk_size_tokens: 5\n";
        let cfg = load_config_str(yaml).unwrap();
        let s = cfg.streaming.unwrap();
        assert_eq!(s.protocol, "websocket");
        assert_eq!(s.chunk_size_tokens, Some(5));
        assert!(cfg.cluster.is_none());
        assert!(cfg.swarm.is_none());
        assert!(cfg.mcp.is_none());
        assert!(cfg.server.is_none());
        assert!(cfg.perception.is_none());
        assert!(cfg.cognitive.is_none());
        assert!(cfg.tracing_config.is_none());
        assert!(cfg.observability.is_none());
    }

    // ── 34. Cluster default mode = standalone ────────────────────────────────
    #[test]
    fn test_34_cluster_default_mode_standalone() {
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\ncluster:\n  peers: []\n";
        let c = load_config_str(yaml).unwrap().cluster.unwrap();
        assert_eq!(c.mode, "standalone");
    }

    // ── 35. Streaming default protocol = sse ─────────────────────────────────
    #[test]
    fn test_35_streaming_default_protocol_sse() {
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\nstreaming:\n  chunk_size_tokens: 5\n";
        let s = load_config_str(yaml).unwrap().streaming.unwrap();
        assert_eq!(s.protocol, "sse");
    }

    // ── 36. MCP default mode = server ────────────────────────────────────────
    #[test]
    fn test_36_mcp_default_mode_server() {
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\nmcp:\n  server_port: 8090\n";
        let m = load_config_str(yaml).unwrap().mcp.unwrap();
        assert_eq!(m.mode, "server");
    }

    // ── 37. Env-var in cluster node_id ───────────────────────────────────────
    #[test]
    fn test_37_env_var_in_cluster_node_id() {
        std::env::set_var("TEST_NODE_ID_CFG_37", "node-prod-1");
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\ncluster:\n  mode: cluster\n  node_id: ${TEST_NODE_ID_CFG_37}\n";
        let c = load_config_str(yaml).unwrap().cluster.unwrap();
        assert_eq!(c.node_id.as_deref(), Some("node-prod-1"));
        std::env::remove_var("TEST_NODE_ID_CFG_37");
    }

    // ── 38. Env-var in server api_key ─────────────────────────────────────────
    #[test]
    fn test_38_env_var_in_server_api_key() {
        std::env::set_var("TEST_SRV_KEY_CFG_38", "srv-from-env");
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\nserver:\n  port: 8080\n  api_key: ${TEST_SRV_KEY_CFG_38}\n";
        let srv = load_config_str(yaml).unwrap().server.unwrap();
        assert_eq!(srv.api_key.as_deref(), Some("srv-from-env"));
        std::env::remove_var("TEST_SRV_KEY_CFG_38");
    }

    // ── 39. Env-var in MCP auth_token ─────────────────────────────────────────
    #[test]
    fn test_39_env_var_in_mcp_auth_token() {
        std::env::set_var("TEST_MCP_TOKEN_CFG_39", "mcp-from-env");
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\nmcp:\n  mode: server\n  auth_token: ${TEST_MCP_TOKEN_CFG_39}\n";
        let m = load_config_str(yaml).unwrap().mcp.unwrap();
        assert_eq!(m.auth_token.as_deref(), Some("mcp-from-env"));
        std::env::remove_var("TEST_MCP_TOKEN_CFG_39");
    }

    // ── 40. Env-var in observability otel_endpoint ────────────────────────────
    #[test]
    fn test_40_env_var_in_observability_endpoint() {
        std::env::set_var("TEST_OTEL_EP_CFG_40", "http://my-collector:4317");
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\nobservability:\n  otel_endpoint: ${TEST_OTEL_EP_CFG_40}\n  service_name: test-svc\n";
        let obs = load_config_str(yaml).unwrap().observability.unwrap();
        assert_eq!(obs.otel_endpoint.as_deref(), Some("http://my-collector:4317"));
        assert_eq!(obs.service_name.as_deref(), Some("test-svc"));
        std::env::remove_var("TEST_OTEL_EP_CFG_40");
    }
}
