//! Host kernel contract (Phase A — **Connector platform**, no plugin code).
//!
//! Implements checklist §10.1–10.4 **platform-side** contracts until `connector-kerneld`
//! loads real nft/eBPF: profiles, idempotent attach/release, policy revision + intent hash,
//! admission fail-closed, and runtime/metrics surfacing.
//!
//! Env:
//! - `CONNECTOR_KERNEL_ENFORCE=1` — admission requires an **active** host attachment for egress-capable ops.
//! - `CONNECTOR_KERNEL_FAIL_CLOSED=1` (default when enforce=1) — deny if not attached / failed.
//! - `CONNECTOR_KERNEL_FAIL_CLOSED=0` — **degraded allow** with audit (not recommended for prod).
//! - `CONNECTOR_KERNEL_SIMULATE_ATTACH_FAIL=1` — attach returns Failed (tests only).
//! - `CONNECTOR_LICENSE_ENFORCE=1` — admission gate denies all agent ops when `LicenseInfo::valid_until` has passed; `GET /api/v1/kernel/status` includes `license` for `connector-kerneld` to deny egress at systemd.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::license::LicenseInfo;
use crate::state::SharedState;

// ── Public config (read from environment; supports hot toggle without rebuild) ─────────────

/// True when host kernel enforcement is required for egress-capable admission paths.
pub fn kernel_enforce_enabled() -> bool {
    matches!(
        std::env::var("CONNECTOR_KERNEL_ENFORCE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// When enforce is on: deny admission if attachment is not Active (default true).
/// License facts for `connector-kerneld` / systemd (same payload as `GET /api/v1/kernel/status` → `data.license`).
pub fn license_block_for_kernel_snapshot(lic: &LicenseInfo) -> serde_json::Value {
    let now = Utc::now().timestamp();
    let time_valid = lic.is_time_valid(now);
    let materialization_revision = lic.host_materialization_revision(now);
    json!({
        "schema": "connector_kernel_license_v1",
        "tier": format!("{:?}", lic.tier),
        "instance_id": &lic.instance_id,
        "valid_until_unix_secs": lic.valid_until,
        "time_valid": time_valid,
        "max_agents": lic.max_agents,
        "max_packets": lic.max_packets,
        "retention_days": lic.retention_days,
        "materialization_revision": materialization_revision,
    })
}

pub fn kernel_fail_closed() -> bool {
    if !kernel_enforce_enabled() {
        return false;
    }
    !matches!(
        std::env::var("CONNECTOR_KERNEL_FAIL_CLOSED")
            .ok()
            .as_deref(),
        Some("0") | Some("false") | Some("no")
    )
}

fn simulate_attach_fail() -> bool {
    matches!(
        std::env::var("CONNECTOR_KERNEL_SIMULATE_ATTACH_FAIL")
            .ok()
            .as_deref(),
        Some("1") | Some("true")
    )
}

// ── State machine ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostApplyState {
    Pending,
    /// Real connector-kerneld BPF/nft/cgroup apply succeeded.
    Active,
    /// In-process stub only — must NEVER satisfy `CONNECTOR_KERNEL_ENFORCE` admission.
    Simulated,
    Failed,
}

impl HostApplyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostApplyState::Pending => "pending",
            HostApplyState::Active => "active",
            HostApplyState::Simulated => "simulated",
            HostApplyState::Failed => "failed",
        }
    }

    /// Admission-ready only when a real host apply completed.
    pub fn is_host_ready(&self) -> bool {
        matches!(self, HostApplyState::Active)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KernelProfileRecord {
    pub profile_id: String,
    pub policy_revision: u64,
    pub intent_hash: String,
    pub source: String,
    pub created_at_ms: i64,
    pub allow_hostnames: Vec<String>,
    pub egress_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentKernelAttachment {
    pub profile_id: String,
    pub policy_revision: u64,
    pub host_apply_state: HostApplyState,
    pub cgroup_path: Option<String>,
    pub bpf_pin_prefix: String,
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
    pub denied_connect_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroVmCell {
    pub cell_id: String,
    pub core_id: String,
    pub max_cells_per_core: u8,
    pub shard_cpu_limit_pct: f64,
    pub async_batch_enabled: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroVmShard {
    pub cell_id: String,
    pub shard_id: String,
    pub replicas: u32,
    pub max_agents: u32,
    pub cpu_limit_pct: f64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMicroVmPlacement {
    pub agent_pid: String,
    pub cell_id: String,
    pub shard_id: String,
    pub core_id: String,
    pub replica_ordinal: u32,
    pub requested_cpu_pct: f64,
    pub async_batch: bool,
    pub scheduled_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareUsageSample {
    pub ts_ms: i64,
    pub agent_pid: String,
    pub core_id: String,
    pub cell_id: String,
    pub shard_id: String,
    pub cpu_pct: f64,
    pub mem_mb: f64,
    pub io_kbps: f64,
}

pub struct KernelHostState {
    next_revision: AtomicU64,
    profiles: Mutex<HashMap<String, KernelProfileRecord>>,
    agents: Mutex<HashMap<String, AgentKernelAttachment>>,
    /// Monotonic attach attempts (idempotent retries increment).
    attach_total: AtomicU64,
    release_total: AtomicU64,
    deny_admission_total: AtomicU64,
    last_apply_latency_us: AtomicU64,
    cells: Mutex<HashMap<String, MicroVmCell>>,
    shards: Mutex<HashMap<String, MicroVmShard>>,
    placements: Mutex<HashMap<String, AgentMicroVmPlacement>>,
    usage_ring: Mutex<VecDeque<HardwareUsageSample>>,
}

impl KernelHostState {
    pub fn new() -> Self {
        Self {
            next_revision: AtomicU64::new(1),
            profiles: Mutex::new(HashMap::new()),
            agents: Mutex::new(HashMap::new()),
            attach_total: AtomicU64::new(0),
            release_total: AtomicU64::new(0),
            deny_admission_total: AtomicU64::new(0),
            last_apply_latency_us: AtomicU64::new(0),
            cells: Mutex::new(HashMap::new()),
            shards: Mutex::new(HashMap::new()),
            placements: Mutex::new(HashMap::new()),
            usage_ring: Mutex::new(VecDeque::with_capacity(4096)),
        }
    }

    pub fn deny_admission_total(&self) -> u64 {
        self.deny_admission_total.load(Ordering::Relaxed)
    }

    pub fn attach_total(&self) -> u64 {
        self.attach_total.load(Ordering::Relaxed)
    }

    pub fn release_total(&self) -> u64 {
        self.release_total.load(Ordering::Relaxed)
    }

    pub fn last_apply_latency_us(&self) -> u64 {
        self.last_apply_latency_us.load(Ordering::Relaxed)
    }

    /// Admission: must be Active when enforce + fail-closed.
    pub fn agent_attachment(&self, agent_pid: &str) -> Option<AgentKernelAttachment> {
        self.agents.lock().ok()?.get(agent_pid).cloned()
    }

    pub fn record_admission_deny(&self) {
        self.deny_admission_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot_json(&self) -> serde_json::Value {
        let profiles: Vec<_> = self
            .profiles
            .lock()
            .map(|p| p.values().cloned().collect())
            .unwrap_or_default();
        let mut agents: Vec<_> = self
            .agents
            .lock()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        json!({
                            "agent_pid": k,
                            "attachment": v,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        agents.sort_by(|a: &serde_json::Value, b| {
            a.get("agent_pid")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .cmp(b.get("agent_pid").and_then(|x| x.as_str()).unwrap_or(""))
        });
        json!({
            "kernel_enforce_enabled": kernel_enforce_enabled(),
            "kernel_fail_closed": kernel_fail_closed(),
            "bpf_pin_prefix_default": "/sys/fs/bpf/connector",
            "nft_table_hint": "inet filter connector_host",
            "profiles": profiles,
            "agents": agents,
            "counters": {
                "attach_total": self.attach_total.load(Ordering::Relaxed),
                "release_total": self.release_total.load(Ordering::Relaxed),
                "admission_denied_kernel_total": self.deny_admission_total.load(Ordering::Relaxed),
                "last_apply_latency_us": self.last_apply_latency_us.load(Ordering::Relaxed),
            },
            "microvm": self.microvm_topology_json(),
            "note": "Stub controller: attach → Simulated (not Active). Active requires real connector-kerneld BPF/nft apply.",
            "honesty": "simulated_topology_until_kerneld",
        })
    }

    fn shard_key(cell_id: &str, shard_id: &str) -> String {
        format!("{cell_id}:{shard_id}")
    }

    pub fn microvm_topology_json(&self) -> serde_json::Value {
        let cells: Vec<_> = self
            .cells
            .lock()
            .expect("cells mutex poisoned")
            .values()
            .cloned()
            .collect();
        let shards: Vec<_> = self
            .shards
            .lock()
            .expect("shards mutex poisoned")
            .values()
            .cloned()
            .collect();
        let placements: Vec<_> = self
            .placements
            .lock()
            .expect("placements mutex poisoned")
            .values()
            .cloned()
            .collect();
        json!({
            "constraints": {
                "max_cells_per_core": 2,
                "core_to_cell_ratio_hint": "1 core can run up to 2 cells",
                "shard_cpu_soft_limit_default_pct": 70.0,
                "shard_agents_target_min": 10,
                "shard_agents_target_max": 20
            },
            "cells": cells,
            "shards": shards,
            "placements": placements,
        })
    }

    pub fn microvm_rollup_json(&self) -> serde_json::Value {
        let samples: Vec<_> = self
            .usage_ring
            .lock()
            .expect("usage_ring mutex poisoned")
            .iter()
            .cloned()
            .collect();

        let mut by_agent: HashMap<String, (f64, f64, f64, u64)> = HashMap::new();
        let mut by_cell: HashMap<String, (f64, f64, f64, u64)> = HashMap::new();
        let mut by_shard: HashMap<String, (f64, f64, f64, u64)> = HashMap::new();
        let mut by_core: HashMap<String, (f64, f64, f64, u64)> = HashMap::new();

        for s in &samples {
            let update = |m: &mut HashMap<String, (f64, f64, f64, u64)>,
                          key: &str,
                          s: &HardwareUsageSample| {
                let e = m.entry(key.to_string()).or_insert((0.0, 0.0, 0.0, 0));
                e.0 += s.cpu_pct;
                e.1 += s.mem_mb;
                e.2 += s.io_kbps;
                e.3 += 1;
            };
            update(&mut by_agent, &s.agent_pid, s);
            update(&mut by_cell, &s.cell_id, s);
            update(&mut by_shard, &format!("{}:{}", s.cell_id, s.shard_id), s);
            update(&mut by_core, &s.core_id, s);
        }

        let fold = |m: HashMap<String, (f64, f64, f64, u64)>| -> Vec<serde_json::Value> {
            m.into_iter()
                .map(|(id, (cpu, mem, io, n))| {
                    json!({
                        "id": id,
                        "avg_cpu_pct": if n > 0 { cpu / n as f64 } else { 0.0 },
                        "avg_mem_mb": if n > 0 { mem / n as f64 } else { 0.0 },
                        "avg_io_kbps": if n > 0 { io / n as f64 } else { 0.0 },
                        "samples": n
                    })
                })
                .collect()
        };

        json!({
            "window_samples": samples.len(),
            "by_agent": fold(by_agent),
            "by_cell": fold(by_cell),
            "by_shard": fold(by_shard),
            "by_core": fold(by_core),
        })
    }

    pub fn microvm_carpenter_plan_json(&self) -> serde_json::Value {
        let placements = self.placements.lock().expect("placements mutex poisoned");
        let mut shard_agent_count: HashMap<String, u32> = HashMap::new();
        for p in placements.values() {
            *shard_agent_count
                .entry(Self::shard_key(&p.cell_id, &p.shard_id))
                .or_insert(0) += 1;
        }
        drop(placements);
        let shards = self.shards.lock().expect("shards mutex poisoned");
        let mut plan = Vec::new();
        for (k, sh) in shards.iter() {
            let count = shard_agent_count.get(k).copied().unwrap_or(0);
            let desired_replicas = ((count as f64) / 15.0).ceil().max(1.0) as u32;
            let action = if desired_replicas > sh.replicas {
                "scale_out"
            } else if desired_replicas < sh.replicas {
                "scale_in"
            } else {
                "steady"
            };
            plan.push(json!({
                "cell_id": sh.cell_id,
                "shard_id": sh.shard_id,
                "agents": count,
                "current_replicas": sh.replicas,
                "desired_replicas": desired_replicas,
                "action": action,
                "reason": "target 10-20 agents per shard replica (15 midpoint)"
            }));
        }
        json!({
            "planner": "connector-kernel-carpenter-v0",
            "plan": plan
        })
    }

    /// Single JSON artifact for security / GRC review: kernel snapshot + ledger contracts + plugin list (K3 in cage strategy doc).
    pub fn cage_manifest_json(&self) -> serde_json::Value {
        let preset = std::env::var("CONNECTOR_PRESET").unwrap_or_default();
        let env_name = std::env::var("CONNECTOR_ENV").unwrap_or_default();
        json!({
            "cage_manifest_schema": "connector_cage_manifest_v1",
            "generated_at": Utc::now().to_rfc3339(),
            "connector_preset": preset,
            "connector_env": env_name,
            "ledger_contracts": {
                "connector_kernel_host": "policy_revision_monotonic_v1",
                "tracetramp_trace_events": "tracetramp_append_only_ledger_v1",
                "witnessctl_tracetramp_handoff": "witnessctl_tracetramp_handoff_v1"
            },
            "first_party_plugins": [
                "tracetramp", "witnessctl", "devguard", "conductor", "relay",
                "agentloop", "ledgerlens", "engram", "agentpassport"
            ],
            "kernel_host_snapshot": self.snapshot_json(),
            "documentation_hints": [
                "platform/docs/arch/CONNECTOR_KERNEL_CAGE_AND_LEDGER.md",
                "platform/docs/arch/AIOS_ADVANCED_CAGE_OUTCOME.md",
                "platform/connector-kerneld/README.md"
            ]
        })
    }

    fn intent_hash(allow: &[String], egress_mode: &str, profile_id: &str) -> String {
        use sha2::{Digest, Sha256};
        let canon = serde_json::json!({
            "profile_id": profile_id,
            "allow_hostnames": allow,
            "egress_mode": egress_mode,
        });
        let s = canon.to_string();
        hex::encode(Sha256::digest(s.as_bytes()))
    }

    /// Idempotent: same profile body → same `policy_revision`; content change → new revision.
    pub fn upsert_profile(
        &self,
        profile_id: String,
        allow_hostnames: Vec<String>,
        egress_mode: String,
        source: String,
    ) -> KernelProfileRecord {
        let intent = Self::intent_hash(&allow_hostnames, &egress_mode, &profile_id);
        let mut guard = self
            .profiles
            .lock()
            .expect("kernel_host profiles mutex poisoned");
        if let Some(existing) = guard.get(&profile_id) {
            if existing.intent_hash == intent {
                return existing.clone();
            }
        }
        let rev = self.next_revision.fetch_add(1, Ordering::SeqCst);
        let now = chrono::Utc::now().timestamp_millis();
        let rec = KernelProfileRecord {
            profile_id: profile_id.clone(),
            policy_revision: rev,
            intent_hash: intent,
            source,
            created_at_ms: now,
            allow_hostnames,
            egress_mode,
        };
        guard.insert(profile_id, rec.clone());
        rec
    }

    /// Idempotent attach: same `(pid, profile_id, revision)` while Active → no-op success.
    pub fn attach_agent(
        &self,
        agent_pid: &str,
        profile_id: &str,
    ) -> Result<AgentKernelAttachment, String> {
        let t0 = Instant::now();
        self.attach_total.fetch_add(1, Ordering::Relaxed);

        let prof = self
            .profiles
            .lock()
            .expect("profiles mutex poisoned")
            .get(profile_id)
            .cloned()
            .ok_or_else(|| format!("unknown profile_id: {}", profile_id))?;

        let mut ag = self.agents.lock().expect("agents mutex poisoned");
        if let Some(cur) = ag.get(agent_pid) {
            // Idempotent for Simulated or Active at same revision.
            if matches!(
                cur.host_apply_state,
                HostApplyState::Active | HostApplyState::Simulated
            ) && cur.profile_id == profile_id
                && cur.policy_revision == prof.policy_revision
            {
                let us = t0.elapsed().as_micros() as u64;
                self.last_apply_latency_us.store(us, Ordering::Relaxed);
                return Ok(cur.clone());
            }
        }

        if simulate_attach_fail() {
            let row = AgentKernelAttachment {
                profile_id: profile_id.to_string(),
                policy_revision: prof.policy_revision,
                host_apply_state: HostApplyState::Failed,
                cgroup_path: None,
                bpf_pin_prefix: format!("/sys/fs/bpf/connector/{}", agent_pid),
                last_error: Some("CONNECTOR_KERNEL_SIMULATE_ATTACH_FAIL".into()),
                updated_at_ms: chrono::Utc::now().timestamp_millis(),
                denied_connect_total: 0,
            };
            ag.insert(agent_pid.to_string(), row.clone());
            let us = t0.elapsed().as_micros() as u64;
            self.last_apply_latency_us.store(us, Ordering::Relaxed);
            return Err("simulated attach failure".into());
        }

        // Production: in-process controller cannot mint Simulated as a successful attach.
        // Active is only via confirm_real_host_apply (kerneld ACK).
        if crate::connector_profile::is_productionish_env() {
            let row = AgentKernelAttachment {
                profile_id: profile_id.to_string(),
                policy_revision: prof.policy_revision,
                host_apply_state: HostApplyState::Failed,
                cgroup_path: None,
                bpf_pin_prefix: format!("/sys/fs/bpf/connector/{}", agent_pid),
                last_error: Some(
                    "host_apply_requires_kerneld — production refuses Simulated attach; connector-kerneld ACK required".into(),
                ),
                updated_at_ms: chrono::Utc::now().timestamp_millis(),
                denied_connect_total: 0,
            };
            ag.insert(agent_pid.to_string(), row.clone());
            let us = t0.elapsed().as_micros() as u64;
            self.last_apply_latency_us.store(us, Ordering::Relaxed);
            return Err("host_apply_requires_kerneld".into());
        }

        // Lab: in-process controller cannot claim Active (no BPF/nft). Paths are declared only.
        let row = AgentKernelAttachment {
            profile_id: profile_id.to_string(),
            policy_revision: prof.policy_revision,
            host_apply_state: HostApplyState::Simulated,
            cgroup_path: Some(format!(
                "/sys/fs/cgroup/connector.slice/connector-agent-{}.scope",
                agent_pid
            )),
            bpf_pin_prefix: format!("/sys/fs/bpf/connector/{}", agent_pid),
            last_error: Some(
                "host_apply_simulated — connector-kerneld not applied; not admission-ready".into(),
            ),
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
            denied_connect_total: 0,
        };
        ag.insert(agent_pid.to_string(), row.clone());
        let us = t0.elapsed().as_micros() as u64;
        self.last_apply_latency_us.store(us, Ordering::Relaxed);
        Ok(row)
    }

    /// Mark attachment Active only after a real kerneld ACK (not used by stub attach).
    pub fn confirm_real_host_apply(
        &self,
        agent_pid: &str,
        cgroup_path: Option<String>,
        bpf_pin_prefix: Option<String>,
    ) -> Result<AgentKernelAttachment, String> {
        self.confirm_real_host_apply_with_note(agent_pid, cgroup_path, bpf_pin_prefix, None)
    }

    pub fn confirm_real_host_apply_with_note(
        &self,
        agent_pid: &str,
        cgroup_path: Option<String>,
        bpf_pin_prefix: Option<String>,
        note: Option<String>,
    ) -> Result<AgentKernelAttachment, String> {
        let mut ag = self.agents.lock().expect("agents mutex poisoned");
        let cur = ag
            .get_mut(agent_pid)
            .ok_or_else(|| format!("no attachment for {agent_pid}"))?;
        cur.host_apply_state = HostApplyState::Active;
        if let Some(p) = cgroup_path {
            cur.cgroup_path = Some(p);
        }
        if let Some(p) = bpf_pin_prefix {
            cur.bpf_pin_prefix = p;
        }
        cur.last_error = note;
        cur.updated_at_ms = chrono::Utc::now().timestamp_millis();
        Ok(cur.clone())
    }

    /// Idempotent release: remove attachment if present.
    pub fn release_agent(&self, agent_pid: &str) {
        self.release_total.fetch_add(1, Ordering::Relaxed);
        let mut ag = self.agents.lock().expect("agents mutex poisoned");
        ag.remove(agent_pid);
    }

    pub fn upsert_cell(&self, req: UpsertCellRequest) -> Result<MicroVmCell, String> {
        if req.cell_id.trim().is_empty() || req.core_id.trim().is_empty() {
            return Err("cell_id and core_id are required".into());
        }
        let max_cells_per_core = req.max_cells_per_core.unwrap_or(2).clamp(1, 2);
        let shard_cpu_limit_pct = req.shard_cpu_limit_pct.unwrap_or(70.0).clamp(5.0, 90.0);
        let mut cells = self.cells.lock().expect("cells mutex poisoned");
        let cell = MicroVmCell {
            cell_id: req.cell_id.trim().to_string(),
            core_id: req.core_id.trim().to_string(),
            max_cells_per_core,
            shard_cpu_limit_pct,
            async_batch_enabled: req.async_batch_enabled.unwrap_or(true),
            updated_at_ms: Utc::now().timestamp_millis(),
        };
        cells.insert(cell.cell_id.clone(), cell.clone());
        Ok(cell)
    }

    pub fn upsert_shard(&self, req: UpsertShardRequest) -> Result<MicroVmShard, String> {
        if req.cell_id.trim().is_empty() || req.shard_id.trim().is_empty() {
            return Err("cell_id and shard_id are required".into());
        }
        let cells = self.cells.lock().expect("cells mutex poisoned");
        let Some(cell) = cells.get(req.cell_id.trim()) else {
            return Err(format!("unknown cell_id {}", req.cell_id.trim()));
        };
        let shard = MicroVmShard {
            cell_id: cell.cell_id.clone(),
            shard_id: req.shard_id.trim().to_string(),
            replicas: req.replicas.unwrap_or(1).clamp(1, 64),
            max_agents: req.max_agents.unwrap_or(20).clamp(10, 20),
            cpu_limit_pct: req
                .cpu_limit_pct
                .unwrap_or(cell.shard_cpu_limit_pct)
                .clamp(5.0, 90.0),
            updated_at_ms: Utc::now().timestamp_millis(),
        };
        drop(cells);
        self.shards.lock().expect("shards mutex poisoned").insert(
            Self::shard_key(&shard.cell_id, &shard.shard_id),
            shard.clone(),
        );
        Ok(shard)
    }

    pub fn schedule_agent_microvm(
        &self,
        agent_pid: &str,
        req: ScheduleAgentRequest,
    ) -> Result<AgentMicroVmPlacement, String> {
        if agent_pid.trim().is_empty() {
            return Err("agent pid required".into());
        }
        let cells = self.cells.lock().expect("cells mutex poisoned");
        let cell = cells
            .get(req.cell_id.trim())
            .ok_or_else(|| format!("unknown cell {}", req.cell_id.trim()))?
            .clone();
        let same_core_cells = cells.values().filter(|c| c.core_id == cell.core_id).count();
        if same_core_cells > cell.max_cells_per_core as usize {
            return Err(format!(
                "core {} already has {} cells (max {})",
                cell.core_id, same_core_cells, cell.max_cells_per_core
            ));
        }
        drop(cells);

        let shard_key = Self::shard_key(&cell.cell_id, req.shard_id.trim());
        let shard = self
            .shards
            .lock()
            .expect("shards mutex poisoned")
            .get(&shard_key)
            .cloned()
            .ok_or_else(|| format!("unknown shard {} in cell {}", req.shard_id, cell.cell_id))?;

        let mut placements = self.placements.lock().expect("placements mutex poisoned");
        let shard_agents = placements
            .values()
            .filter(|p| p.cell_id == cell.cell_id && p.shard_id == shard.shard_id)
            .count() as u32;
        if shard_agents >= shard.max_agents {
            return Err(format!(
                "shard {} reached agent cap {}",
                shard.shard_id, shard.max_agents
            ));
        }
        let requested_cpu_pct = req.requested_cpu_pct.unwrap_or(3.5).max(0.1);
        let existing_shard_cpu: f64 = placements
            .values()
            .filter(|p| p.cell_id == cell.cell_id && p.shard_id == shard.shard_id)
            .map(|p| p.requested_cpu_pct)
            .sum();
        if existing_shard_cpu + requested_cpu_pct > shard.cpu_limit_pct {
            return Err(format!(
                "shard {} cpu budget exceeded: {:.2}% + {:.2}% > {:.2}%",
                shard.shard_id, existing_shard_cpu, requested_cpu_pct, shard.cpu_limit_pct
            ));
        }

        let placement = AgentMicroVmPlacement {
            agent_pid: agent_pid.trim().to_string(),
            cell_id: cell.cell_id.clone(),
            shard_id: shard.shard_id.clone(),
            core_id: cell.core_id.clone(),
            replica_ordinal: req.replica_ordinal.unwrap_or(0),
            requested_cpu_pct,
            async_batch: req.async_batch.unwrap_or(cell.async_batch_enabled),
            scheduled_at_ms: Utc::now().timestamp_millis(),
        };
        placements.insert(placement.agent_pid.clone(), placement.clone());
        Ok(placement)
    }

    pub fn record_hardware_usage(
        &self,
        agent_pid: &str,
        req: RecordHardwareUsageRequest,
    ) -> Result<HardwareUsageSample, String> {
        let placement = self
            .placements
            .lock()
            .expect("placements mutex poisoned")
            .get(agent_pid)
            .cloned()
            .ok_or_else(|| format!("no placement for agent {}", agent_pid))?;
        let sample = HardwareUsageSample {
            ts_ms: Utc::now().timestamp_millis(),
            agent_pid: agent_pid.to_string(),
            core_id: placement.core_id,
            cell_id: placement.cell_id,
            shard_id: placement.shard_id,
            cpu_pct: req.cpu_pct.clamp(0.0, 100.0),
            mem_mb: req.mem_mb.max(0.0),
            io_kbps: req.io_kbps.max(0.0),
        };
        let mut ring = self.usage_ring.lock().expect("usage_ring mutex poisoned");
        if ring.len() >= 4096 {
            ring.pop_front();
        }
        ring.push_back(sample.clone());
        Ok(sample)
    }

    /// Remove one microVM placement assignment for an agent/plugin id.
    pub fn unschedule_agent_microvm(&self, agent_pid: &str) -> bool {
        self.placements
            .lock()
            .expect("placements mutex poisoned")
            .remove(agent_pid)
            .is_some()
    }

    /// Read-only capacity preflight for bulk scheduling into one cell/shard.
    pub fn preview_schedule_capacity(
        &self,
        cell_id: &str,
        shard_id: &str,
        additional_agents: u32,
        requested_cpu_pct_each: f64,
    ) -> Result<serde_json::Value, String> {
        let cell_id = cell_id.trim();
        let shard_id = shard_id.trim();
        if cell_id.is_empty() || shard_id.is_empty() {
            return Err("cell_id and shard_id are required".into());
        }
        let requested_cpu_pct_each = requested_cpu_pct_each.max(0.0);

        let cells = self.cells.lock().expect("cells mutex poisoned");
        let existing_cell = cells.get(cell_id).cloned();
        let core_id = existing_cell
            .as_ref()
            .map(|c| c.core_id.clone())
            .unwrap_or_else(|| cell_id.to_string());
        let max_cells_per_core = existing_cell
            .as_ref()
            .map(|c| c.max_cells_per_core)
            .unwrap_or(2);
        let same_core_cells = cells.values().filter(|c| c.core_id == core_id).count();
        let projected_core_cells = if existing_cell.is_some() {
            same_core_cells
        } else {
            same_core_cells + 1
        };
        if projected_core_cells > max_cells_per_core as usize {
            return Err(format!(
                "core {} would have {} cells (max {})",
                core_id, projected_core_cells, max_cells_per_core
            ));
        }
        drop(cells);

        let shard_key = Self::shard_key(cell_id, shard_id);
        let shards = self.shards.lock().expect("shards mutex poisoned");
        let existing_shard = shards.get(&shard_key).cloned();
        drop(shards);
        let max_agents = existing_shard.as_ref().map(|s| s.max_agents).unwrap_or(20);
        let cpu_limit_pct = existing_shard
            .as_ref()
            .map(|s| s.cpu_limit_pct)
            .unwrap_or(70.0);

        let placements = self.placements.lock().expect("placements mutex poisoned");
        let existing_agents = placements
            .values()
            .filter(|p| p.cell_id == cell_id && p.shard_id == shard_id)
            .count() as u32;
        let existing_cpu_pct: f64 = placements
            .values()
            .filter(|p| p.cell_id == cell_id && p.shard_id == shard_id)
            .map(|p| p.requested_cpu_pct)
            .sum();
        let projected_agents = existing_agents.saturating_add(additional_agents);
        if projected_agents > max_agents {
            return Err(format!(
                "shard {} reached agent cap: {} + {} > {}",
                shard_id, existing_agents, additional_agents, max_agents
            ));
        }
        let projected_cpu_pct =
            existing_cpu_pct + (requested_cpu_pct_each * additional_agents as f64);
        if projected_cpu_pct > cpu_limit_pct {
            return Err(format!(
                "shard {} cpu budget exceeded: {:.2}% + {:.2}% > {:.2}%",
                shard_id,
                existing_cpu_pct,
                requested_cpu_pct_each * additional_agents as f64,
                cpu_limit_pct
            ));
        }
        Ok(json!({
            "cell_id": cell_id,
            "shard_id": shard_id,
            "cell_exists": existing_cell.is_some(),
            "shard_exists": existing_shard.is_some(),
            "existing_agents": existing_agents,
            "additional_agents": additional_agents,
            "projected_agents": projected_agents,
            "max_agents": max_agents,
            "existing_cpu_pct": existing_cpu_pct,
            "additional_cpu_pct": requested_cpu_pct_each * additional_agents as f64,
            "projected_cpu_pct": projected_cpu_pct,
            "cpu_limit_pct": cpu_limit_pct,
            "requested_cpu_pct_each": requested_cpu_pct_each,
            "ok": true
        }))
    }
}

// ── HTTP API ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateKernelProfileRequest {
    pub profile_id: String,
    #[serde(default)]
    pub allow_hostnames: Vec<String>,
    #[serde(default = "default_egress_mode")]
    pub egress_mode: String,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_egress_mode() -> String {
    "proxy_only".into()
}
fn default_source() -> String {
    "api".into()
}

#[derive(Debug, Deserialize)]
pub struct AttachKernelRequest {
    pub profile_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpsertCellRequest {
    pub cell_id: String,
    pub core_id: String,
    #[serde(default)]
    pub max_cells_per_core: Option<u8>,
    #[serde(default)]
    pub shard_cpu_limit_pct: Option<f64>,
    #[serde(default)]
    pub async_batch_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertShardRequest {
    pub cell_id: String,
    pub shard_id: String,
    #[serde(default)]
    pub replicas: Option<u32>,
    #[serde(default)]
    pub max_agents: Option<u32>,
    #[serde(default)]
    pub cpu_limit_pct: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct ScheduleAgentRequest {
    pub cell_id: String,
    pub shard_id: String,
    #[serde(default)]
    pub replica_ordinal: Option<u32>,
    #[serde(default)]
    pub requested_cpu_pct: Option<f64>,
    #[serde(default)]
    pub async_batch: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RecordHardwareUsageRequest {
    pub cpu_pct: f64,
    pub mem_mb: f64,
    pub io_kbps: f64,
}

pub async fn post_kernel_profile(
    State(state): State<SharedState>,
    Json(req): Json<CreateKernelProfileRequest>,
) -> impl IntoResponse {
    if req.profile_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "profile_id required" })),
        )
            .into_response();
    }
    let rec = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned")
        .upsert_profile(
            req.profile_id.trim().to_string(),
            req.allow_hostnames,
            req.egress_mode,
            req.source,
        );
    state.metrics.kernel_profile_upserts_total.inc();
    (StatusCode::OK, Json(json!({ "ok": true, "data": rec }))).into_response()
}

pub async fn post_kernel_attach(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<AttachKernelRequest>,
) -> impl IntoResponse {
    let mut host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    match host.attach_agent(&pid, &req.profile_id) {
        Ok(att) => {
            drop(host);
            state.metrics.kernel_attach_success_total.inc();
            (StatusCode::OK, Json(json!({ "ok": true, "data": att }))).into_response()
        }
        Err(e) => {
            drop(host);
            state.metrics.kernel_attach_failures_total.inc();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": e })),
            )
                .into_response()
        }
    }
}

pub async fn get_kernel_status(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    match host.agent_attachment(&pid) {
        Some(att) => (StatusCode::OK, Json(json!({ "ok": true, "data": att }))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": { "code": "kernel_attachment_not_found", "message": format!("no host attachment for {}", pid) }
            })),
        )
            .into_response(),
    }
}

pub async fn post_kernel_release(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> impl IntoResponse {
    state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned")
        .release_agent(&pid);
    state.metrics.kernel_release_total.inc();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "data": { "released": pid } })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ConfirmHostApplyRequest {
    #[serde(default)]
    pub cgroup_path: Option<String>,
    #[serde(default)]
    pub bpf_pin_prefix: Option<String>,
    /// Honest apply backend: `systemd_dropin` | `kerneld` | `bpf` | …
    #[serde(default)]
    pub apply_backend: Option<String>,
    /// Set by connector-kerneld after real bpffs pins exist.
    #[serde(default)]
    pub ebpf_probe_ok: Option<bool>,
}

/// Probe local bpffs for Connector eBPF pins (same-host kerneld apply).
pub fn probe_ebpf_pins(agent_pid: Option<&str>) -> bool {
    crate::kernel::matrix_host_egress::probe_ebpf_pins(agent_pid)
}

/// POST /kernel/agents/:pid/confirm-host-apply — kerneld ACK → Active (B32 OS path).
pub async fn post_kernel_confirm_host_apply(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<ConfirmHostApplyRequest>,
) -> impl IntoResponse {
    let bpf_flag = std::env::var("CONNECTOR_KERNEL_BPF_APPLIED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let probe_ok = req.ebpf_probe_ok.unwrap_or(false)
        || probe_ebpf_pins(Some(&pid))
        || req
            .bpf_pin_prefix
            .as_ref()
            .map(|p| {
                let prog = std::path::Path::new(p).join("prog");
                prog.exists()
            })
            .unwrap_or(false);
    let backend = req.apply_backend.unwrap_or_else(|| {
        if probe_ok || bpf_flag {
            "bpf".into()
        } else {
            "systemd_dropin".into()
        }
    });
    // Refuse claiming BPF Active without real pins or break-glass flag.
    if backend.eq_ignore_ascii_case("bpf") && !probe_ok && !bpf_flag {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "bpf_not_applied",
                "message": "Cannot confirm BPF Active without bpffs pins (connector-kerneld ebpf-load) or CONNECTOR_KERNEL_BPF_APPLIED=1 break-glass",
                "hint": "connector-kerneld ebpf-load --agent <pid> [--cgroup /sys/fs/cgroup/...]",
            })),
        )
            .into_response();
    }
    let honesty_note = if backend.eq_ignore_ascii_case("bpf") && probe_ok {
        "Active = eBPF host path — bpffs pins verified (real load)."
    } else if backend.eq_ignore_ascii_case("bpf") && bpf_flag {
        "Active = eBPF claimed via CONNECTOR_KERNEL_BPF_APPLIED break-glass (pins not probed)."
    } else {
        "Active = host control plane applied (systemd drop-in / kerneld). Not eBPF unless bpf backend + pins."
    };
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    match host.confirm_real_host_apply_with_note(
        &pid,
        req.cgroup_path,
        req.bpf_pin_prefix,
        Some(format!("host_apply_confirmed:{backend}")),
    ) {
        Ok(att) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "data": att,
                "honesty": {
                    "apply_backend": backend,
                    "bpf_applied_flag": bpf_flag,
                    "ebpf_probe_ok": probe_ok,
                    "note": honesty_note,
                }
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_kernel_global_status(State(state): State<SharedState>) -> impl IntoResponse {
    let mut snap = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned")
        .snapshot_json();
    if let Some(obj) = snap.as_object_mut() {
        obj.insert(
            "license".to_string(),
            license_block_for_kernel_snapshot(&state.license),
        );
        obj.insert(
            "flow_lease".to_string(),
            crate::substrate::flow_lease::lease_snapshot(state.as_ref()),
        );
    }
    (StatusCode::OK, Json(json!({ "ok": true, "data": snap }))).into_response()
}

pub async fn get_kernel_cage_manifest(State(state): State<SharedState>) -> impl IntoResponse {
    let mut manifest = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned")
        .cage_manifest_json();
    if let Some(host_snap) = manifest
        .get_mut("kernel_host_snapshot")
        .and_then(|v| v.as_object_mut())
    {
        host_snap.insert(
            "license".to_string(),
            license_block_for_kernel_snapshot(&state.license),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "data": manifest })),
    )
        .into_response()
}

pub async fn post_microvm_cell(
    State(state): State<SharedState>,
    Json(req): Json<UpsertCellRequest>,
) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    match host.upsert_cell(req) {
        Ok(cell) => (StatusCode::OK, Json(json!({ "ok": true, "data": cell }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

pub async fn post_microvm_shard(
    State(state): State<SharedState>,
    Json(req): Json<UpsertShardRequest>,
) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    match host.upsert_shard(req) {
        Ok(shard) => (StatusCode::OK, Json(json!({ "ok": true, "data": shard }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

pub async fn post_microvm_schedule_agent(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<ScheduleAgentRequest>,
) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    match host.schedule_agent_microvm(&pid, req) {
        Ok(p) => (StatusCode::OK, Json(json!({ "ok": true, "data": p }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

pub async fn post_microvm_usage(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<RecordHardwareUsageRequest>,
) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    match host.record_hardware_usage(&pid, req) {
        Ok(s) => (StatusCode::OK, Json(json!({ "ok": true, "data": s }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_microvm_topology(State(state): State<SharedState>) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "data": host.microvm_topology_json() })),
    )
        .into_response()
}

pub async fn get_microvm_rollup(State(state): State<SharedState>) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "data": host.microvm_rollup_json() })),
    )
        .into_response()
}

pub async fn get_microvm_carpenter_plan(State(state): State<SharedState>) -> impl IntoResponse {
    let host = state
        .kernel_host
        .lock()
        .expect("kernel_host mutex poisoned");
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "data": host.microvm_carpenter_plan_json() })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_idempotent_same_intent() {
        let h = KernelHostState::new();
        let a = h.upsert_profile(
            "p1".into(),
            vec!["api.openai.com".into()],
            "proxy_only".into(),
            "t".into(),
        );
        let b = h.upsert_profile(
            "p1".into(),
            vec!["api.openai.com".into()],
            "proxy_only".into(),
            "t".into(),
        );
        assert_eq!(a.policy_revision, b.policy_revision);
    }

    #[test]
    fn profile_new_revision_when_intent_changes() {
        let h = KernelHostState::new();
        let a = h.upsert_profile("p1".into(), vec![], "proxy_only".into(), "t".into());
        let b = h.upsert_profile(
            "p1".into(),
            vec!["x".into()],
            "proxy_only".into(),
            "t".into(),
        );
        assert_ne!(a.policy_revision, b.policy_revision);
    }

    #[test]
    fn attach_idempotent() {
        let h = KernelHostState::new();
        h.upsert_profile("p1".into(), vec![], "allowlist".into(), "t".into());
        let x = h.attach_agent("agent-1", "p1").unwrap();
        let y = h.attach_agent("agent-1", "p1").unwrap();
        assert_eq!(x.policy_revision, y.policy_revision);
        assert_eq!(x.host_apply_state, HostApplyState::Simulated);
        assert!(!x.host_apply_state.is_host_ready());
    }

    #[test]
    fn release_idempotent() {
        let h = KernelHostState::new();
        h.upsert_profile("p1".into(), vec![], "allowlist".into(), "t".into());
        h.attach_agent("agent-1", "p1").unwrap();
        h.release_agent("agent-1");
        h.release_agent("agent-1");
        assert!(h.agent_attachment("agent-1").is_none());
    }

    #[test]
    fn cage_manifest_has_schema_and_ledger_contracts() {
        let h = KernelHostState::new();
        let m = h.cage_manifest_json();
        assert_eq!(
            m.get("cage_manifest_schema").and_then(|x| x.as_str()),
            Some("connector_cage_manifest_v1")
        );
        assert!(m.get("ledger_contracts").is_some());
        assert!(m.get("kernel_host_snapshot").is_some());
    }

    #[test]
    fn license_block_matches_connector_kernel_license_v1() {
        let mut lic = crate::license::LicenseInfo::community();
        lic.valid_until = Some(chrono::Utc::now().timestamp() + 86_400);
        let v = license_block_for_kernel_snapshot(&lic);
        assert_eq!(
            v.get("schema").and_then(|x| x.as_str()),
            Some("connector_kernel_license_v1")
        );
        assert_eq!(v.get("time_valid").and_then(|x| x.as_bool()), Some(true));
        assert!(v
            .get("materialization_revision")
            .and_then(|x| x.as_u64())
            .is_some());
    }

    #[test]
    fn license_block_marks_expired_when_valid_until_passed() {
        let mut lic = crate::license::LicenseInfo::community();
        lic.valid_until = Some(1);
        let v = license_block_for_kernel_snapshot(&lic);
        assert_eq!(v.get("time_valid").and_then(|x| x.as_bool()), Some(false));
    }

    #[test]
    fn cage_manifest_merge_inserts_license_like_http_handler() {
        let h = KernelHostState::new();
        let mut manifest = h.cage_manifest_json();
        let lic = crate::license::LicenseInfo::community();
        if let Some(host_snap) = manifest
            .get_mut("kernel_host_snapshot")
            .and_then(|v| v.as_object_mut())
        {
            host_snap.insert(
                "license".to_string(),
                license_block_for_kernel_snapshot(&lic),
            );
        }
        let ks = manifest.get("kernel_host_snapshot").expect("snapshot");
        assert_eq!(
            ks.get("license")
                .and_then(|l| l.get("schema"))
                .and_then(|s| s.as_str()),
            Some("connector_kernel_license_v1")
        );
    }

    #[test]
    fn microvm_schedule_enforces_cpu_budget() {
        let h = KernelHostState::new();
        h.upsert_cell(UpsertCellRequest {
            cell_id: "cell-a".into(),
            core_id: "core-0".into(),
            max_cells_per_core: Some(2),
            shard_cpu_limit_pct: Some(70.0),
            async_batch_enabled: Some(true),
        })
        .unwrap();
        h.upsert_shard(UpsertShardRequest {
            cell_id: "cell-a".into(),
            shard_id: "s1".into(),
            replicas: Some(1),
            max_agents: Some(20),
            cpu_limit_pct: Some(70.0),
        })
        .unwrap();
        h.schedule_agent_microvm(
            "a1",
            ScheduleAgentRequest {
                cell_id: "cell-a".into(),
                shard_id: "s1".into(),
                replica_ordinal: Some(0),
                requested_cpu_pct: Some(50.0),
                async_batch: Some(true),
            },
        )
        .unwrap();
        let e = h
            .schedule_agent_microvm(
                "a2",
                ScheduleAgentRequest {
                    cell_id: "cell-a".into(),
                    shard_id: "s1".into(),
                    replica_ordinal: Some(0),
                    requested_cpu_pct: Some(25.0),
                    async_batch: Some(true),
                },
            )
            .err()
            .unwrap_or_default();
        assert!(e.contains("cpu budget exceeded"));
    }

    #[test]
    fn microvm_rollup_contains_agent_sample() {
        let h = KernelHostState::new();
        h.upsert_cell(UpsertCellRequest {
            cell_id: "cell-a".into(),
            core_id: "core-0".into(),
            max_cells_per_core: None,
            shard_cpu_limit_pct: None,
            async_batch_enabled: None,
        })
        .unwrap();
        h.upsert_shard(UpsertShardRequest {
            cell_id: "cell-a".into(),
            shard_id: "s1".into(),
            replicas: None,
            max_agents: None,
            cpu_limit_pct: None,
        })
        .unwrap();
        h.schedule_agent_microvm(
            "agent-x",
            ScheduleAgentRequest {
                cell_id: "cell-a".into(),
                shard_id: "s1".into(),
                replica_ordinal: None,
                requested_cpu_pct: None,
                async_batch: None,
            },
        )
        .unwrap();
        h.record_hardware_usage(
            "agent-x",
            RecordHardwareUsageRequest {
                cpu_pct: 21.0,
                mem_mb: 128.0,
                io_kbps: 42.0,
            },
        )
        .unwrap();
        let roll = h.microvm_rollup_json();
        let cnt = roll
            .get("by_agent")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert!(cnt >= 1);
    }

    #[test]
    fn preview_schedule_capacity_reports_projected_limits() {
        let h = KernelHostState::new();
        h.upsert_cell(UpsertCellRequest {
            cell_id: "cell-a".into(),
            core_id: "core-0".into(),
            max_cells_per_core: Some(2),
            shard_cpu_limit_pct: Some(70.0),
            async_batch_enabled: Some(true),
        })
        .unwrap();
        h.upsert_shard(UpsertShardRequest {
            cell_id: "cell-a".into(),
            shard_id: "s1".into(),
            replicas: Some(1),
            max_agents: Some(20),
            cpu_limit_pct: Some(70.0),
        })
        .unwrap();
        h.schedule_agent_microvm(
            "a1",
            ScheduleAgentRequest {
                cell_id: "cell-a".into(),
                shard_id: "s1".into(),
                replica_ordinal: None,
                requested_cpu_pct: Some(20.0),
                async_batch: None,
            },
        )
        .unwrap();
        let v = h
            .preview_schedule_capacity("cell-a", "s1", 2, 10.0)
            .expect("preview");
        assert_eq!(v.get("projected_agents").and_then(|x| x.as_u64()), Some(3));
        assert_eq!(v.get("max_agents").and_then(|x| x.as_u64()), Some(20));
        assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(true));
    }
}
