pub mod acs;
pub mod actionlog;
pub mod admission;
pub mod agent_identity;
pub mod agent_index_integration;
pub mod agent_lifecycle;
pub mod agent_reaper;
pub mod agent_resource_manager;
pub mod agent_traffic_police;
pub mod agents;
pub mod keycloak_agents;
pub mod connector_demo;
pub mod agent_loop;
pub mod browser_explorer;
pub mod fleet_chain;
pub mod workbench;
pub mod aios;
pub mod auto_allocator;
pub mod augmented_task;
pub mod cell_spiffe;
pub mod chain_tree;
pub mod cls;
pub mod cls_handlers;
pub mod command_center;
pub mod compliance;
pub mod council;
pub mod debug;
pub mod disputes;
pub mod experiments;
pub mod extension_host;
pub mod ha_federation;
pub mod history;
pub mod insights;
pub mod intelligence_authority;
pub mod intelligence_quick;
pub mod kecs_calculator;
pub mod knowledge_pipeline;
pub mod licensing;
pub mod mcp_hosting;
pub mod membership_heartbeat;
pub mod memory;
pub mod memory_graph;
pub mod memory_plane;
pub mod memory_vector_box;
pub mod mesh_channel;
pub mod mesh_join_token;
pub mod mesh_knowledge_plane;
pub mod mesh_status;
pub mod monitor;
pub mod multiagent;
pub mod namespace_isolation;
pub mod notebook;
pub mod notifications;
pub mod observability;
pub mod orchestration_intelligence;
pub mod payment;
pub mod pipeline;
pub mod prompts;
pub mod proof;
pub mod proof_chain;
pub mod report_center;
pub mod runtime_control;
pub mod runtime_egress;
pub mod runtime_enforcement;
pub mod scim;
pub mod security_signals;
pub mod support_bundle;
pub mod tools;
pub mod topology_center;
pub mod webhooks;
pub mod world_gateway;
// ── Sellable services (OSS hidden capabilities surfaced) ──
pub mod apps_catalog;
pub mod author_portal;
pub mod cage_proof;
pub mod catalog;
pub mod connector_yaml;
pub mod context;
pub mod custom_domain_routing;
pub mod deployment;
pub mod devguard;
pub mod devguard_github;
pub mod devguard_local_profile;
pub mod devguard_proxy;
pub mod devguard_team;
pub mod devguard_workspace;
pub mod economy;
pub mod exec_guard;
pub mod federation_policy;
pub mod firewall_config;
pub mod forensics;
pub mod fs_guard;
pub mod grounding;
pub mod hub_mirrors;
pub mod hub_workflow_publish;
pub mod kernel_host;
pub mod llm_output_contract;
pub mod marketplace;
pub mod moment;
pub mod object_fabric;
pub mod orchestrator;
pub mod phase5_operator_env;
pub mod playground;
pub mod playground_demo;
pub mod playground_export;
pub mod plugin_cage_proxy;
pub mod plugin_condo;
pub mod plugin_configure;
pub mod plugin_cpkg;
pub mod plugin_crash_recovery;
pub mod plugin_depends;
pub mod plugin_egress_allowlist;
pub mod plugin_hub;
pub mod plugin_lifecycle;
pub mod plugin_marketplace;
pub mod plugin_matrix;
pub mod plugin_runtime_inventory;
pub mod plugin_tier_scheduler;
pub mod plugin_upstream_probe;
pub mod plugins_status;
pub mod policy_config;
pub mod policy_lineage;
pub mod secrets;
pub mod settings_llms;
pub mod soas;
pub mod aacr;
pub mod aipsprt_api;
pub mod settings_secrets;
pub mod settings_system;
pub mod setup;
pub mod supervisor_inventory;
pub mod telemetry_playground;
pub mod tracetramp_proxy;
pub mod unified_health;
pub mod verify;
pub mod witnessctl_proxy;
pub mod workflow_catalog_sync;
pub mod workflow_cls_execution;
pub mod workflow_cnp;
pub mod workflow_bootstrap;
pub mod workflow_reference;
pub mod workflow_runner;
pub mod workflow_runtime;
pub mod workload_lifecycle;
// ── Exposure Gap fills (EXPOSURE_GAP.md P0/P1) ──
pub mod aapi;
pub mod cognitive;
pub mod cpkg_gloo_burnin;
pub mod memory2;
// ── Protocol Bridges + Safety + Distributed Infra ──
pub mod cnp_surface;
pub mod conp_protocol;
pub mod fabric;
pub mod infra;
pub mod missions;
pub mod protocols;
pub mod safety;
pub mod surface_http;
pub mod surface_monitor_live;
pub mod surfaces;

// ── Resource Management ──
pub use agent_index_integration::{AgentIndexIntegration, SharedAgentIndexIntegration};
pub use agent_resource_manager::{AgentResourceManager, SharedAgentResourceManager};
pub use auto_allocator::{AutoAllocator, SharedAutoAllocator};

// ── FIX BUG-064/065: Network & Security Infrastructure ──
// crate::security accessible directly

// ── FIX BUG-021: Distributed Systems ──
// crate::distributed accessible directly

// ── CLS & Protocols ──
// crate::cls accessible directly

// ── Knowledge, Knot & Storage Systems ──
// crate::knowledge, crate::knot, crate::storage accessible directly

// ── FIX BUG-031/032/033/035/036/038: Data Security & Privacy ──
// crate::data accessible directly

// ── Compliance & Proof Systems ──
// crate::compliance, crate::proof, crate::policy accessible directly

// ── AI Gateway (D2 fix — OpenAI-compatible proxy with automatic audit) ──
pub mod gateway;
pub mod gateway_hooks;
// ── AIOS-A6: Agent Registry + Deploy ──
pub mod deploy;
pub mod registry;
// ── BIZ-4: Billing Service ──
pub mod billing;
// ── BIZ-7: Analytics / activation funnel telemetry ──
pub mod analytics;
// ── AMA-2: Episode object service ──
pub mod episodes;
// ── AMA-5: Policy check (access(2) analog) ──
pub mod policy_check;
// ── AMA-6: Signed audit receipts ──
pub mod audit_receipts;
// ── ConnectorMap Books — Accounting-inspired operational ledger ──
pub mod books;
// ── Asset & Knowledge Pipeline ──
pub mod adaptive;
pub mod anthropic_gateway;
pub mod assets;
pub mod workspace_projection;
pub mod workspace_records;
pub mod workspace_followthrough;
pub mod iia_runtime;
pub mod knowledge_transfer;
pub mod secret_broker;
