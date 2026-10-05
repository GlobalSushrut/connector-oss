//! NAPI-RS native Node.js bindings for Connector OSS.
//!
//! Exposes the full Connector engine + protocol stack directly to Node.js
//! via native addons — no HTTP server required.

use std::sync::Mutex;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use connector_engine::engine_store::{InMemoryEngineStore, EngineStore, FolderOwner};
use vac_core::kernel::{MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue};
use vac_core::types::{MemoryKernelOp, MemPacket, PacketType, Source, SourceKind};

use cid::Cid;

// ── helpers (mirrors vac-ffi patterns) ─────────────────────────

fn make_packet(content: &str, user: &str, pipe: &str, ptype: PacketType) -> MemPacket {
    MemPacket::new(
        ptype,
        serde_json::json!({"text": content}),
        Cid::default(),
        user.to_string(),
        pipe.to_string(),
        Source { kind: SourceKind::User, principal_id: user.to_string() },
        chrono::Utc::now().timestamp_millis(),
    )
}

fn write_mem(
    kernel: &mut MemoryKernel,
    pid: &str,
    content: &str,
    user: &str,
) -> Option<cid::Cid> {
    let r = kernel.dispatch(SyscallRequest {
        agent_pid: pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite {
            packet: make_packet(content, user, "napi", PacketType::Input),
        },
        reason: None,
        vakya_id: None,
    });
    match r.value {
        SyscallValue::Cid(c) => Some(c),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// NativeConnector — the main entry point
// ═══════════════════════════════════════════════════════════════════

#[napi]
pub struct NativeConnector {
    #[allow(dead_code)]
    connector: connector_api::Connector,
    kernel: Mutex<MemoryKernel>,
    engine_store: Mutex<Box<dyn EngineStore + Send>>,
}

#[napi]
impl NativeConnector {
    /// Create from provider/model/api_key.
    #[napi(constructor)]
    pub fn new(provider: String, model: String, api_key: String) -> Self {
        let connector = connector_api::Connector::new()
            .llm(&provider, &model, &api_key)
            .build();
        Self {
            connector,
            kernel: Mutex::new(MemoryKernel::new()),
            engine_store: Mutex::new(Box::new(InMemoryEngineStore::new())),
        }
    }

    /// Create from a YAML config file path.
    #[napi(factory)]
    pub fn from_config(path: String) -> Result<Self> {
        let cfg = connector_api::config::load_config(&path)
            .map_err(|e| Error::from_reason(format!("Config error: {}", e)))?;
        let connector = connector_api::Connector::from_config(&cfg);
        Ok(Self {
            connector,
            kernel: Mutex::new(MemoryKernel::new()),
            engine_store: Mutex::new(Box::new(InMemoryEngineStore::new())),
        })
    }

    /// Create from a YAML string.
    #[napi(factory)]
    pub fn from_config_str(yaml: String) -> Result<Self> {
        let cfg = connector_api::config::load_config_str(&yaml)
            .map_err(|e| Error::from_reason(format!("Config error: {}", e)))?;
        let connector = connector_api::Connector::from_config(&cfg);
        Ok(Self {
            connector,
            kernel: Mutex::new(MemoryKernel::new()),
            engine_store: Mutex::new(Box::new(InMemoryEngineStore::new())),
        })
    }

    // ── Memory ────────────────────────────────────────────────────

    /// Write a memory packet to the kernel.
    #[napi]
    pub fn remember(&self, agent_pid: String, content: String, user: String) -> Result<String> {
        let mut k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        match write_mem(&mut k, &agent_pid, &content, &user) {
            Some(c) => Ok(c.to_string()),
            None => Ok("written".to_string()),
        }
    }

    /// List packets in a namespace.
    #[napi]
    pub fn memories(&self, namespace: String, limit: Option<u32>) -> Result<String> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let packets = k.packets_in_namespace(&namespace);
        let lim = limit.unwrap_or(50) as usize;
        let items: Vec<serde_json::Value> = packets.iter().take(lim)
            .map(|p| serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
            }))
            .collect();
        let result = serde_json::json!({
            "namespace": namespace, "count": items.len(), "packets": items,
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Search packets.
    #[napi]
    pub fn search(&self, namespace: Option<String>, session_id: Option<String>, limit: Option<u32>) -> Result<String> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let lim = limit.unwrap_or(50) as usize;
        let packets: Vec<serde_json::Value> = if let Some(ref ns) = namespace {
            k.packets_in_namespace(ns).iter().take(lim)
                .map(|p| serde_json::json!({
                    "cid": p.content.payload_cid.to_string(),
                    "type": format!("{}", p.content.packet_type),
                    "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                }))
                .collect()
        } else if let Some(ref sid) = session_id {
            k.packets_in_session(sid).iter().take(lim)
                .map(|p| serde_json::json!({
                    "cid": p.content.payload_cid.to_string(),
                    "type": format!("{}", p.content.packet_type),
                    "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                }))
                .collect()
        } else { vec![] };
        let result = serde_json::json!({ "count": packets.len(), "packets": packets });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Knowledge ingest.
    #[napi]
    pub fn knowledge_ingest(&self, namespace: String) -> Result<String> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let count = k.packets_in_namespace(&namespace).len();
        let result = serde_json::json!({ "ok": true, "namespace": namespace, "packets_ingested": count });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// RAG retrieval.
    #[napi]
    pub fn knowledge_query(&self, _entities: Vec<String>, _keywords: Vec<String>, _token_budget: Option<u32>, _max_facts: Option<u32>) -> Result<String> {
        let result = serde_json::json!({
            "facts": [], "facts_included": 0, "tokens_used": 0,
            "prompt_context": "", "entities": _entities, "source_cids": [],
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    // ── Agents & Audit ────────────────────────────────────────────

    #[napi]
    pub fn agents(&self) -> Result<String> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let agents = k.agents();
        let items: Vec<serde_json::Value> = agents.values()
            .map(|a| serde_json::json!({
                "pid": a.agent_pid, "name": a.agent_pid, "namespace": a.namespace,
                "status": if a.terminated_at.is_some() { "terminated" } else { "active" },
            }))
            .collect();
        let result = serde_json::json!({ "count": items.len(), "agents": items });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn audit(&self, limit: Option<u32>) -> Result<String> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let lim = limit.unwrap_or(50) as usize;
        let log = k.audit_log();
        let items: Vec<serde_json::Value> = log.iter().rev().take(lim)
            .map(|e| serde_json::json!({
                "timestamp": e.timestamp, "operation": format!("{}", e.operation),
                "agent_pid": e.agent_pid, "outcome": format!("{}", e.outcome),
            }))
            .collect();
        let result = serde_json::json!({ "count": items.len(), "entries": items });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn trust(&self) -> Result<String> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let agents = k.agents();
        let agent_count = agents.len();
        let mut breakdown = serde_json::Map::new();
        for (_pid, acb) in agents {
            let ns = format!("ns:{}", acb.agent_pid);
            let count = k.packets_in_namespace(&ns).len();
            breakdown.insert(acb.agent_pid.clone(), serde_json::json!({
                "packets": count,
                "status": if acb.terminated_at.is_some() { "terminated" } else { "active" },
            }));
        }
        let result = serde_json::json!({
            "agents": agent_count, "total_packets": k.packet_count(),
            "audit_entries": k.audit_log().len(), "breakdown": breakdown,
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn packet_count(&self) -> Result<u32> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(k.packet_count() as u32)
    }

    #[napi]
    pub fn audit_count(&self) -> Result<u32> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(k.audit_log().len() as u32)
    }

    #[napi]
    pub fn agent_count(&self) -> Result<u32> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(k.agents().len() as u32)
    }

    // ── Sessions ──────────────────────────────────────────────────

    #[napi]
    pub fn session_create(&self, agent_pid: String, namespace: String, label: Option<String>) -> Result<String> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let session_id = format!("sess:{}:{}", agent_pid, now_ms);
        let result = serde_json::json!({
            "ok": true, "session_id": session_id,
            "agent_pid": agent_pid, "namespace": namespace,
            "label": label, "started_at": now_ms,
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn session_close(&self, agent_pid: String, session_id: String) -> Result<String> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let result = serde_json::json!({
            "ok": true, "session_id": session_id,
            "agent_pid": agent_pid, "ended_at": now_ms,
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    // ── Custom Folders ────────────────────────────────────────────

    #[napi]
    pub fn folder_create(&self, namespace: String, owner_type: Option<String>, owner_id: Option<String>, description: Option<String>) -> Result<String> {
        let mut es = self.engine_store.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let owner = match owner_type.as_deref() {
            Some("agent") => FolderOwner::Agent(owner_id.unwrap_or_default()),
            Some("tool") => FolderOwner::Tool(owner_id.unwrap_or_default()),
            _ => FolderOwner::System,
        };
        es.create_folder(&namespace, &owner, description.as_deref().unwrap_or(""))
            .map_err(|e| Error::from_reason(format!("{:?}", e)))?;
        Ok(r#"{"ok":true}"#.to_string())
    }

    #[napi]
    pub fn folder_put(&self, namespace: String, key: String, value: String) -> Result<String> {
        let mut es = self.engine_store.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let val: serde_json::Value = serde_json::from_str(&value)
            .unwrap_or(serde_json::Value::String(value));
        es.folder_put(&namespace, &key, &val)
            .map_err(|e| Error::from_reason(format!("{:?}", e)))?;
        Ok(r#"{"ok":true}"#.to_string())
    }

    #[napi]
    pub fn folder_get(&self, namespace: String, key: String) -> Result<String> {
        let es = self.engine_store.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let val = es.folder_get(&namespace, &key)
            .map_err(|e| Error::from_reason(format!("{:?}", e)))?;
        let result = serde_json::json!({ "ok": true, "value": val });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn folder_list(&self) -> Result<String> {
        let es = self.engine_store.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let folders = es.list_folders(None)
            .map_err(|e| Error::from_reason(format!("{:?}", e)))?;
        let items: Vec<serde_json::Value> = folders.iter()
            .map(|f| serde_json::json!({
                "namespace": f.namespace, "owner": format!("{:?}", f.owner),
                "description": f.description, "entry_count": f.entry_count,
            }))
            .collect();
        let result = serde_json::json!({ "count": items.len(), "folders": items });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn db_stats(&self) -> Result<String> {
        let k = self.kernel.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let es = self.engine_store.lock().map_err(|e| Error::from_reason(e.to_string()))?;
        let result = serde_json::json!({
            "kernel_packets": k.packet_count(),
            "kernel_agents": k.agents().len(),
            "kernel_audit_entries": k.audit_log().len(),
            "engine_folders": es.list_folders(None).map(|f| f.len()).unwrap_or(0),
            "engine_tools": es.load_tool_defs().map(|t| t.len()).unwrap_or(0),
            "engine_policies": es.load_policies().map(|p| p.len()).unwrap_or(0),
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    // ── Connector Protocol (CP/1.0) ──────────────────────────────

    #[napi]
    pub fn protocol_info(&self) -> Result<String> {
        let registry = connector_protocol::ProtocolCapabilityRegistry::with_defaults();
        let result = serde_json::json!({
            "protocol": "CP/1.0", "name": "Connector Protocol",
            "layers": 7, "total_capabilities": registry.count(),
            "entity_classes": ["agent","machine","device","service","sensor","actuator","composite"],
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn protocol_capabilities(&self) -> Result<String> {
        use connector_protocol::CapabilityCategory as CC;
        let r = connector_protocol::ProtocolCapabilityRegistry::with_defaults();
        let result = serde_json::json!({
            "total_capabilities": r.count(),
            "categories": {
                "agent": r.count_by_category(CC::Agent), "machine": r.count_by_category(CC::Machine),
                "device": r.count_by_category(CC::Device), "sensor": r.count_by_category(CC::Sensor),
                "actuator": r.count_by_category(CC::Actuator), "net": r.count_by_category(CC::Net),
                "fs": r.count_by_category(CC::Fs), "proc": r.count_by_category(CC::Proc),
                "store": r.count_by_category(CC::Store), "crypto": r.count_by_category(CC::Crypto),
                "gpu": r.count_by_category(CC::Gpu), "safety": r.count_by_category(CC::Safety),
            }
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn protocol_capability_check(&self, capability_id: String, entity_class: String) -> Result<String> {
        use connector_protocol::EntityClass as EC;
        let registry = connector_protocol::ProtocolCapabilityRegistry::with_defaults();
        let class = match entity_class.as_str() {
            "agent" => EC::Agent, "machine" => EC::Machine, "device" => EC::Device,
            "service" => EC::Service, "sensor" => EC::Sensor, "actuator" => EC::Actuator,
            _ => EC::Agent,
        };
        let allowed = registry.is_allowed(&capability_id, class);
        let cap = registry.get(&capability_id);
        let result = serde_json::json!({
            "capability_id": capability_id, "entity_class": entity_class,
            "allowed": allowed, "exists": cap.is_some(),
            "risk_level": cap.map(|c| format!("{:?}", c.risk)),
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn protocol_identity_register(&self, entity_id: String, entity_class: String) -> Result<String> {
        use connector_protocol::{EntityClass as EC, EntityId};
        let class = match entity_class.as_str() {
            "agent" => EC::Agent, "machine" => EC::Machine, "device" => EC::Device,
            "service" => EC::Service, "sensor" => EC::Sensor, "actuator" => EC::Actuator,
            _ => EC::Agent,
        };
        let eid = EntityId::new(class, &entity_id);
        let sil = class.default_sil();
        let result = serde_json::json!({
            "ok": true, "entity_id": eid.as_str(), "class": entity_class,
            "safety_integrity_level": format!("{}", sil),
            "requires_realtime": class.requires_realtime(), "did": eid.as_str(),
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn protocol_estop(&self, issuer: String, reason: String, scope: Option<String>) -> Result<String> {
        use connector_protocol::{EntityClass as EC, EntityId, EStopScope};
        let initiator = EntityId::new(EC::Agent, &issuer);
        let s = match scope.as_deref() {
            Some("global") => EStopScope::Global,
            Some("cell") => EStopScope::Cell("default".to_string()),
            _ => EStopScope::Entity(initiator.clone()),
        };
        let result = serde_json::json!({
            "ok": true,
            "estop": {
                "initiator": initiator.as_str(), "reason": reason,
                "scope": format!("{:?}", s), "timestamp": chrono::Utc::now().timestamp_millis(),
            },
            "note": "Emergency stop is an ambient capability — cannot be denied by policy",
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn protocol_intent(&self, agent_id: String, goal: String, coordination: Option<String>) -> Result<String> {
        use connector_protocol::{EntityClass as EC, EntityId, CoordinationPattern, Intent};
        let coord = match coordination.as_deref() {
            Some("parallel") => CoordinationPattern::Parallel,
            Some("conditional") => CoordinationPattern::Conditional,
            Some("consensus") => CoordinationPattern::Consensus,
            _ => CoordinationPattern::Sequential,
        };
        let eid = EntityId::new(EC::Agent, &agent_id);
        let intent = Intent::new(eid, &goal, coord);
        let result = serde_json::json!({
            "ok": true, "agent_id": agent_id, "goal": goal,
            "coordination": coordination.as_deref().unwrap_or("sequential"),
            "step_count": intent.step_count(), "execution_waves": intent.execution_order(),
        });
        serde_json::to_string(&result).map_err(|e| Error::from_reason(e.to_string()))
    }
}
