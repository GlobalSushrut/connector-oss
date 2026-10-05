//! V2 Health API — Health and maturity scores
//!
//! Routes:
//!   GET    /api/v2/health             — System health overview
//!   GET    /api/v2/health/maturity    — Maturity levels
//!   GET    /api/v2/health/agents      — All agents health

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;
use super::V2Response;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub status: String,
    pub agent_count: usize,
    pub running_agents: usize,
    pub suspended_agents: usize,
    pub session_count: usize,
    pub memory_packets: usize,
    pub audit_entries: usize,
    pub average_kecs: f64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaturityLevel {
    pub level: String,
    pub kecs_range: String,
    pub description: String,
    pub agent_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_id: String,
    pub agent_name: String,
    pub kecs_score: f64,
    pub maturity_level: String,
    pub status: String,
    pub components: HealthComponents,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthComponents {
    pub k_vn: f64,
    pub s_renyi: f64,
    pub k_topo: f64,
}

#[derive(Debug, Deserialize, Default)]
pub struct HealthQuery {
    pub include_details: Option<bool>,
}

/// GET /api/v2/health — System health overview
pub async fn get_health(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Query(_query): Query<HealthQuery>,
) -> V2Response<SystemHealth> {
    let (agent_count, running, suspended, session_count, packet_count, audit_count, avg_kecs) = {
        let kernel = state.kernel.lock().unwrap();
        let mut engine_store = state.engine_store.lock().unwrap();
        
        let kernel_agents = kernel.all_agents();
        let running = kernel_agents.iter().filter(|a| a.status == vac_core::types::AgentStatus::Running).count();
        let suspended = kernel_agents.iter().filter(|a| a.status == vac_core::types::AgentStatus::Suspended).count();
        
        // Calculate average KECS
        let mut kecs_sum = 0.0;
        let mut kecs_count = 0;
        for agent in &kernel_agents {
            if let Some(kecs_data) = crate::services::agents::folder_get_kecs_unified(&mut *engine_store, &agent.agent_pid) {
                if let Some(kecs) = kecs_data.get("kecs").and_then(|k| k.as_f64()) {
                    kecs_sum += kecs;
                    kecs_count += 1;
                }
            }
        }
        let avg_kecs = if kecs_count > 0 { kecs_sum / kecs_count as f64 } else { 0.0 };
        
        (
            kernel_agents.len(),
            running,
            suspended,
            kernel.sessions().len(),
            kernel.all_packets().len(),
            kernel.audit_log().len(),
            avg_kecs,
        )
    };
    
    let health = SystemHealth {
        status: "healthy".to_string(),
        agent_count,
        running_agents: running,
        suspended_agents: suspended,
        session_count,
        memory_packets: packet_count,
        audit_entries: audit_count,
        average_kecs: (avg_kecs * 100.0).round() / 100.0,
        timestamp: super::format_iso8601(chrono::Utc::now().timestamp_millis()),
    };
    
    V2Response::success(health)
}

/// GET /api/v2/health/maturity — Maturity levels
pub async fn get_maturity(
    State(state): State<SharedState>,
    _headers: HeaderMap,
) -> V2Response<Vec<MaturityLevel>> {
    let levels = {
        let kernel = state.kernel.lock().unwrap();
        let mut engine_store = state.engine_store.lock().unwrap();
        
        let mut expert = 0;
        let mut proficient = 0;
        let mut competent = 0;
        let mut developing = 0;
        let mut novice = 0;
        
        for agent in kernel.all_agents() {
            if let Some(kecs_data) = crate::services::agents::folder_get_kecs_unified(&mut *engine_store, &agent.agent_pid) {
                if let Some(kecs) = kecs_data.get("kecs").and_then(|k| k.as_f64()) {
                    if kecs >= 0.85 {
                        expert += 1;
                    } else if kecs >= 0.70 {
                        proficient += 1;
                    } else if kecs >= 0.55 {
                        competent += 1;
                    } else if kecs >= 0.40 {
                        developing += 1;
                    } else {
                        novice += 1;
                    }
                }
            }
        }
        
        vec![
            MaturityLevel {
                level: "expert".to_string(),
                kecs_range: "≥0.85".to_string(),
                description: "Highly mature, production-ready agents".to_string(),
                agent_count: expert,
            },
            MaturityLevel {
                level: "proficient".to_string(),
                kecs_range: "0.70-0.84".to_string(),
                description: "Well-developed agents with good reliability".to_string(),
                agent_count: proficient,
            },
            MaturityLevel {
                level: "competent".to_string(),
                kecs_range: "0.55-0.69".to_string(),
                description: "Functional agents with room for improvement".to_string(),
                agent_count: competent,
            },
            MaturityLevel {
                level: "developing".to_string(),
                kecs_range: "0.40-0.54".to_string(),
                description: "Agents in early development".to_string(),
                agent_count: developing,
            },
            MaturityLevel {
                level: "novice".to_string(),
                kecs_range: "<0.40".to_string(),
                description: "New or unstable agents requiring attention".to_string(),
                agent_count: novice,
            },
        ]
    };
    
    V2Response::success(levels)
}

/// GET /api/v2/health/agents — All agents health
pub async fn get_agents_health(
    State(state): State<SharedState>,
    _headers: HeaderMap,
) -> V2Response<Vec<AgentHealth>> {
    let agents_health: Vec<AgentHealth> = {
        let kernel = state.kernel.lock().unwrap();
        let mut engine_store = state.engine_store.lock().unwrap();
        
        kernel.all_agents()
            .iter()
            .map(|agent| {
                let (kecs_score, k_vn, s_renyi, k_topo) = 
                    if let Some(kecs_data) = crate::services::agents::folder_get_kecs_unified(&mut *engine_store, &agent.agent_pid) {
                        let kecs = kecs_data.get("kecs").and_then(|k| k.as_f64()).unwrap_or(0.0);
                        let k_vn = kecs_data.get("k_vn").and_then(|k| k.as_f64()).unwrap_or(0.0);
                        let s_renyi = kecs_data.get("s_renyi").and_then(|k| k.as_f64()).unwrap_or(0.0);
                        let k_topo = kecs_data.get("k_topo").and_then(|k| k.as_f64()).unwrap_or(0.0);
                        (kecs, k_vn, s_renyi, k_topo)
                    } else {
                        (0.0, 0.0, 0.0, 0.0)
                    };
                
                let maturity_level = if kecs_score >= 0.85 {
                    "expert"
                } else if kecs_score >= 0.70 {
                    "proficient"
                } else if kecs_score >= 0.55 {
                    "competent"
                } else if kecs_score >= 0.40 {
                    "developing"
                } else {
                    "novice"
                };
                
                AgentHealth {
                    agent_id: agent.agent_pid.clone(),
                    agent_name: agent.agent_name.clone(),
                    kecs_score: (kecs_score * 100.0).round() / 100.0,
                    maturity_level: maturity_level.to_string(),
                    status: format!("{:?}", agent.status),
                    components: HealthComponents {
                        k_vn: (k_vn * 100.0).round() / 100.0,
                        s_renyi: (s_renyi * 100.0).round() / 100.0,
                        k_topo: (k_topo * 100.0).round() / 100.0,
                    },
                }
            })
            .collect()
    };
    
    V2Response::success(agents_health)
}
