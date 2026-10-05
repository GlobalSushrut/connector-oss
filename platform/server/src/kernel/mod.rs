//! Agent Kernel — operating layer for chartered intelligences.
//!
//! Architecture: `operating_layer` (three sockets, vendor-blind).
//! Matrix: `intelligence_matrix` (Albus SP · WM · VJ · BG-socket).
//! Apps (LangGraph, vLLM, Ollama, Crew) never appear as kernel types.

pub mod action_binding;
pub mod effect_authz;
pub mod isolation_manifest;
pub mod agent_chat;
pub mod workbench_session;
pub mod agent_foundation;
pub mod agent_identity_envelope;
pub mod agent_principal;
pub mod compliance_contract;
pub mod continuity;
pub mod credential_proxy;
pub mod docklock;
pub mod iia_llm_inject;
pub mod forensic_package;
pub mod forensic_rollups;
pub mod forensics;
pub mod decision_trace;
pub mod fabric_task;
pub mod isolation_tiers;
pub mod nsfs;
pub mod agent_cgroup;
pub mod address_cage;
pub mod address_contracts;
pub mod address_dac_api;
pub mod agent_explain;
pub mod intelligence_purge;
pub mod node_fabric;
pub mod acs;
pub mod membrane_posture;
pub mod mission_journal;
pub mod partner_hal;
pub mod sil_interlock;
pub mod intelligence_spec;
pub mod intelligence_matrix;
pub mod operating_layer;
pub mod world_gateway;
pub mod pore_table;
pub mod landlock_child;
pub mod llm_vendor_cut;
pub mod browser_world;
pub mod conp_authority;
pub mod admission_layers;
pub mod aacr;
pub mod aios;
pub mod share_portal;
pub mod vault_seal;
pub mod zt_handshake;
pub mod council;
pub mod ring1_context;
pub mod matrix_isolation;
pub mod matrix_host_egress;
pub mod witnessctl_align;
