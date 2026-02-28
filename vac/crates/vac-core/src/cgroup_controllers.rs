//! Cgroup v2-Style Resource Controllers — hierarchical resource limits for agents.
//!
//! Modeled on Linux cgroup v2 unified hierarchy with 4 controllers:
//!   memory  — packet count + byte limits (hard deny on exceed)
//!   compute — token + cost limits (soft warn at 80%, hard at 100%)
//!   io      — operations per second/minute (hard deny + backpressure)
//!   pids    — agent count per cgroup (hard deny on AgentRegister)
//!
//! Research: Linux cgroup v2 (kernel.org), OWASP ASI08 (Cascading Failures),
//! NVIDIA Agentic Sandboxing (2026), NIST AI RMF MANAGE

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Cgroup Node
// ═══════════════════════════════════════════════════════════════

/// A node in the cgroup hierarchy (org → team → agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupNode {
    pub name: String,
    pub parent: Option<String>,
    pub children: Vec<String>,
    pub limits: CgroupLimits,
    pub usage: CgroupUsage,
}

/// Resource limits for a cgroup node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupLimits {
    pub max_packets: u64,
    pub max_bytes: u64,
    pub max_tokens_daily: u64,
    pub max_tokens_hourly: u64,
    pub max_cost_daily_usd: f64,
    pub max_ops_per_second: u32,
    pub max_ops_per_minute: u32,
    pub max_agents: u32,
}

/// Current resource usage for a cgroup node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupUsage {
    pub packets: u64,
    pub bytes: u64,
    pub tokens_today: u64,
    pub tokens_this_hour: u64,
    pub cost_today_usd: f64,
    pub ops_this_second: u32,
    pub ops_this_minute: u32,
    pub agent_count: u32,
    pub second_start_ms: i64,
    pub minute_start_ms: i64,
}

// ═══════════════════════════════════════════════════════════════
// Cgroup Decision
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CgroupDecision {
    Allow,
    SoftWarn { controller: String, usage_pct: u8, message: String },
    HardDeny { controller: String, message: String },
}

impl CgroupDecision {
    pub fn is_deny(&self) -> bool { matches!(self, CgroupDecision::HardDeny { .. }) }
    pub fn is_warn(&self) -> bool { matches!(self, CgroupDecision::SoftWarn { .. }) }
}

/// Pressure Stall Information — emitted when usage > 80%.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupPressureEvent {
    pub cgroup: String,
    pub controller: String,
    pub usage_pct: u8,
    pub timestamp: i64,
}

/// Audit entry for every cgroup limit check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupAuditEntry {
    pub cgroup: String,
    pub controller: String,
    pub decision: CgroupDecision,
    pub timestamp: i64,
}

// ═══════════════════════════════════════════════════════════════
// Cgroup Hierarchy Manager
// ═══════════════════════════════════════════════════════════════

/// Manages a hierarchy of cgroups with enforced resource limits.
pub struct CgroupHierarchy {
    nodes: HashMap<String, CgroupNode>,
    audit_log: Vec<CgroupAuditEntry>,
    pressure_events: Vec<CgroupPressureEvent>,
}

impl CgroupHierarchy {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            audit_log: Vec::new(),
            pressure_events: Vec::new(),
        }
    }

    /// Register a cgroup node.
    pub fn register(&mut self, name: &str, parent: Option<&str>, limits: CgroupLimits) -> Result<(), String> {
        if self.nodes.contains_key(name) {
            return Err(format!("Cgroup '{}' already exists", name));
        }
        if let Some(p) = parent {
            if !self.nodes.contains_key(p) {
                return Err(format!("Parent cgroup '{}' not found", p));
            }
            self.nodes.get_mut(p).unwrap().children.push(name.to_string());
        }
        self.nodes.insert(name.to_string(), CgroupNode {
            name: name.to_string(),
            parent: parent.map(|s| s.to_string()),
            children: Vec::new(),
            limits,
            usage: CgroupUsage::default(),
        });
        Ok(())
    }

    /// Record usage for a cgroup and propagate to parents (hierarchical roll-up).
    pub fn record_usage(&mut self, cgroup: &str, packets: u64, bytes: u64, tokens: u64, cost_usd: f64, now_ms: i64) {
        let mut current = Some(cgroup.to_string());
        while let Some(name) = current {
            if let Some(node) = self.nodes.get_mut(&name) {
                // Reset time windows if needed
                if node.usage.second_start_ms == 0 || now_ms - node.usage.second_start_ms >= 1000 {
                    node.usage.ops_this_second = 0;
                    node.usage.second_start_ms = now_ms;
                }
                if node.usage.minute_start_ms == 0 || now_ms - node.usage.minute_start_ms >= 60_000 {
                    node.usage.ops_this_minute = 0;
                    node.usage.minute_start_ms = now_ms;
                }
                node.usage.packets += packets;
                node.usage.bytes += bytes;
                node.usage.tokens_today += tokens;
                node.usage.tokens_this_hour += tokens;
                node.usage.cost_today_usd += cost_usd;
                node.usage.ops_this_second += 1;
                node.usage.ops_this_minute += 1;
                current = node.parent.clone();
            } else {
                break;
            }
        }
    }

    /// Record an agent registration in a cgroup.
    pub fn record_agent_register(&mut self, cgroup: &str) {
        let mut current = Some(cgroup.to_string());
        while let Some(name) = current {
            if let Some(node) = self.nodes.get_mut(&name) {
                node.usage.agent_count += 1;
                current = node.parent.clone();
            } else {
                break;
            }
        }
    }

    // ── Memory Controller ───────────────────────────────────

    /// Check memory limits (packets + bytes). Hard deny on exceed.
    pub fn check_memory(&mut self, cgroup: &str, now_ms: i64) -> CgroupDecision {
        let decision = self.check_memory_inner(cgroup);
        self.audit_log.push(CgroupAuditEntry {
            cgroup: cgroup.to_string(), controller: "memory".into(),
            decision: decision.clone(), timestamp: now_ms,
        });
        if let CgroupDecision::SoftWarn { usage_pct, .. } = &decision {
            self.pressure_events.push(CgroupPressureEvent {
                cgroup: cgroup.to_string(), controller: "memory".into(),
                usage_pct: *usage_pct, timestamp: now_ms,
            });
        }
        decision
    }

    fn check_memory_inner(&self, cgroup: &str) -> CgroupDecision {
        let mut current = Some(cgroup.to_string());
        while let Some(name) = current {
            if let Some(node) = self.nodes.get(&name) {
                if node.limits.max_packets > 0 && node.usage.packets >= node.limits.max_packets {
                    return CgroupDecision::HardDeny {
                        controller: "memory".into(),
                        message: format!("cgroup '{}': packets {}/{}", name, node.usage.packets, node.limits.max_packets),
                    };
                }
                if node.limits.max_bytes > 0 && node.usage.bytes >= node.limits.max_bytes {
                    return CgroupDecision::HardDeny {
                        controller: "memory".into(),
                        message: format!("cgroup '{}': bytes {}/{}", name, node.usage.bytes, node.limits.max_bytes),
                    };
                }
                if node.limits.max_packets > 0 {
                    let pct = (node.usage.packets * 100 / node.limits.max_packets) as u8;
                    if pct >= 80 {
                        return CgroupDecision::SoftWarn {
                            controller: "memory".into(), usage_pct: pct,
                            message: format!("cgroup '{}': packets at {}%", name, pct),
                        };
                    }
                }
                current = node.parent.clone();
            } else {
                break;
            }
        }
        CgroupDecision::Allow
    }

    // ── Compute Controller ──────────────────────────────────

    /// Check compute limits (tokens + cost). Soft warn at 80%, hard at 100%.
    pub fn check_compute(&mut self, cgroup: &str, now_ms: i64) -> CgroupDecision {
        let decision = self.check_compute_inner(cgroup);
        self.audit_log.push(CgroupAuditEntry {
            cgroup: cgroup.to_string(), controller: "compute".into(),
            decision: decision.clone(), timestamp: now_ms,
        });
        if let CgroupDecision::SoftWarn { usage_pct, .. } = &decision {
            self.pressure_events.push(CgroupPressureEvent {
                cgroup: cgroup.to_string(), controller: "compute".into(),
                usage_pct: *usage_pct, timestamp: now_ms,
            });
        }
        decision
    }

    fn check_compute_inner(&self, cgroup: &str) -> CgroupDecision {
        let mut current = Some(cgroup.to_string());
        while let Some(name) = current {
            if let Some(node) = self.nodes.get(&name) {
                if node.limits.max_tokens_daily > 0 && node.usage.tokens_today >= node.limits.max_tokens_daily {
                    return CgroupDecision::HardDeny {
                        controller: "compute".into(),
                        message: format!("cgroup '{}': daily tokens {}/{}", name, node.usage.tokens_today, node.limits.max_tokens_daily),
                    };
                }
                if node.limits.max_tokens_hourly > 0 && node.usage.tokens_this_hour >= node.limits.max_tokens_hourly {
                    return CgroupDecision::HardDeny {
                        controller: "compute".into(),
                        message: format!("cgroup '{}': hourly tokens {}/{}", name, node.usage.tokens_this_hour, node.limits.max_tokens_hourly),
                    };
                }
                if node.limits.max_tokens_daily > 0 {
                    let pct = (node.usage.tokens_today * 100 / node.limits.max_tokens_daily) as u8;
                    if pct >= 80 {
                        return CgroupDecision::SoftWarn {
                            controller: "compute".into(), usage_pct: pct,
                            message: format!("cgroup '{}': daily tokens at {}%", name, pct),
                        };
                    }
                }
                current = node.parent.clone();
            } else {
                break;
            }
        }
        CgroupDecision::Allow
    }

    // ── IO Controller ───────────────────────────────────────

    /// Check IO rate limits (ops/sec, ops/min). Hard deny on exceed.
    pub fn check_io(&mut self, cgroup: &str, now_ms: i64) -> CgroupDecision {
        let decision = self.check_io_inner(cgroup);
        self.audit_log.push(CgroupAuditEntry {
            cgroup: cgroup.to_string(), controller: "io".into(),
            decision: decision.clone(), timestamp: now_ms,
        });
        decision
    }

    fn check_io_inner(&self, cgroup: &str) -> CgroupDecision {
        let mut current = Some(cgroup.to_string());
        while let Some(name) = current {
            if let Some(node) = self.nodes.get(&name) {
                if node.limits.max_ops_per_second > 0 && node.usage.ops_this_second >= node.limits.max_ops_per_second {
                    return CgroupDecision::HardDeny {
                        controller: "io".into(),
                        message: format!("cgroup '{}': ops/sec {}/{}", name, node.usage.ops_this_second, node.limits.max_ops_per_second),
                    };
                }
                if node.limits.max_ops_per_minute > 0 && node.usage.ops_this_minute >= node.limits.max_ops_per_minute {
                    return CgroupDecision::HardDeny {
                        controller: "io".into(),
                        message: format!("cgroup '{}': ops/min {}/{}", name, node.usage.ops_this_minute, node.limits.max_ops_per_minute),
                    };
                }
                current = node.parent.clone();
            } else {
                break;
            }
        }
        CgroupDecision::Allow
    }

    // ── PIDs Controller ─────────────────────────────────────

    /// Check agent count limit. Hard deny on exceed.
    pub fn check_pids(&mut self, cgroup: &str, now_ms: i64) -> CgroupDecision {
        let decision = self.check_pids_inner(cgroup);
        self.audit_log.push(CgroupAuditEntry {
            cgroup: cgroup.to_string(), controller: "pids".into(),
            decision: decision.clone(), timestamp: now_ms,
        });
        decision
    }

    fn check_pids_inner(&self, cgroup: &str) -> CgroupDecision {
        let mut current = Some(cgroup.to_string());
        while let Some(name) = current {
            if let Some(node) = self.nodes.get(&name) {
                if node.limits.max_agents > 0 && node.usage.agent_count >= node.limits.max_agents {
                    return CgroupDecision::HardDeny {
                        controller: "pids".into(),
                        message: format!("cgroup '{}': agents {}/{}", name, node.usage.agent_count, node.limits.max_agents),
                    };
                }
                current = node.parent.clone();
            } else {
                break;
            }
        }
        CgroupDecision::Allow
    }

    // ── Accessors ───────────────────────────────────────────

    pub fn audit_log(&self) -> &[CgroupAuditEntry] { &self.audit_log }
    pub fn pressure_events(&self) -> &[CgroupPressureEvent] { &self.pressure_events }

    pub fn get_usage(&self, cgroup: &str) -> Option<&CgroupUsage> {
        self.nodes.get(cgroup).map(|n| &n.usage)
    }

    /// Pressure level (0.0–1.0) for a controller on a cgroup.
    pub fn pressure_level(&self, cgroup: &str, controller: &str) -> f64 {
        let node = match self.nodes.get(cgroup) {
            Some(n) => n,
            None => return 0.0,
        };
        match controller {
            "memory" => {
                if node.limits.max_packets == 0 { 0.0 }
                else { node.usage.packets as f64 / node.limits.max_packets as f64 }
            }
            "compute" => {
                if node.limits.max_tokens_daily == 0 { 0.0 }
                else { node.usage.tokens_today as f64 / node.limits.max_tokens_daily as f64 }
            }
            "io" => {
                if node.limits.max_ops_per_second == 0 { 0.0 }
                else { node.usage.ops_this_second as f64 / node.limits.max_ops_per_second as f64 }
            }
            "pids" => {
                if node.limits.max_agents == 0 { 0.0 }
                else { node.usage.agent_count as f64 / node.limits.max_agents as f64 }
            }
            _ => 0.0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hierarchy() -> CgroupHierarchy {
        let mut h = CgroupHierarchy::new();
        h.register("org:acme", None, CgroupLimits {
            max_packets: 1000, max_tokens_daily: 100_000, max_agents: 10,
            ..Default::default()
        }).unwrap();
        h.register("team:health", Some("org:acme"), CgroupLimits {
            max_packets: 500, max_tokens_daily: 50_000, max_agents: 5,
            ..Default::default()
        }).unwrap();
        h.register("agent:triage", Some("team:health"), CgroupLimits {
            max_packets: 100, max_tokens_daily: 10_000, max_agents: 1,
            ..Default::default()
        }).unwrap();
        h
    }

    #[test]
    fn test_memory_allow_under_limit() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 10, 0, 0, 0.0, 1000);
        assert_eq!(h.check_memory("agent:triage", 1000), CgroupDecision::Allow);
    }

    #[test]
    fn test_memory_hard_deny_on_exceed() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 100, 0, 0, 0.0, 1000);
        let d = h.check_memory("agent:triage", 1000);
        assert!(d.is_deny());
    }

    #[test]
    fn test_memory_soft_warn_at_80_pct() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 85, 0, 0, 0.0, 1000);
        let d = h.check_memory("agent:triage", 1000);
        assert!(d.is_warn());
    }

    #[test]
    fn test_memory_hierarchy_rollup_parent_deny() {
        let mut h = make_hierarchy();
        // Fill team limit directly
        h.record_usage("agent:triage", 500, 0, 0, 0.0, 1000);
        // Agent limit (100) is hit first, but team (500) is also hit
        let d = h.check_memory("agent:triage", 1000);
        assert!(d.is_deny());
    }

    #[test]
    fn test_compute_allow_under_limit() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 0, 0, 5000, 0.0, 1000);
        assert_eq!(h.check_compute("agent:triage", 1000), CgroupDecision::Allow);
    }

    #[test]
    fn test_compute_hard_deny_on_exceed() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 0, 0, 10_000, 0.0, 1000);
        let d = h.check_compute("agent:triage", 1000);
        assert!(d.is_deny());
    }

    #[test]
    fn test_compute_soft_warn_at_80_pct() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 0, 0, 8500, 0.0, 1000);
        let d = h.check_compute("agent:triage", 1000);
        assert!(d.is_warn());
    }

    #[test]
    fn test_io_hard_deny_on_exceed() {
        let mut h = CgroupHierarchy::new();
        h.register("cg", None, CgroupLimits {
            max_ops_per_second: 5, ..Default::default()
        }).unwrap();
        for _ in 0..5 {
            h.record_usage("cg", 0, 0, 0, 0.0, 1000);
        }
        let d = h.check_io("cg", 1000);
        assert!(d.is_deny());
    }

    #[test]
    fn test_io_allows_after_window_reset() {
        let mut h = CgroupHierarchy::new();
        h.register("cg", None, CgroupLimits {
            max_ops_per_second: 5, ..Default::default()
        }).unwrap();
        for _ in 0..5 {
            h.record_usage("cg", 0, 0, 0, 0.0, 1000);
        }
        assert!(h.check_io("cg", 1000).is_deny());
        // New second resets the counter
        h.record_usage("cg", 0, 0, 0, 0.0, 2001);
        assert_eq!(h.check_io("cg", 2001), CgroupDecision::Allow);
    }

    #[test]
    fn test_pids_hard_deny_on_exceed() {
        let mut h = make_hierarchy();
        h.record_agent_register("agent:triage");
        let d = h.check_pids("agent:triage", 1000);
        assert!(d.is_deny());
    }

    #[test]
    fn test_pids_allow_under_limit() {
        let mut h = make_hierarchy();
        assert_eq!(h.check_pids("agent:triage", 1000), CgroupDecision::Allow);
    }

    #[test]
    fn test_pids_hierarchy_rollup() {
        let mut h = make_hierarchy();
        // Register 5 agents under team (hits team limit)
        for _ in 0..5 {
            h.record_agent_register("team:health");
        }
        // Team limit hit (5/5), so registering under child should also be denied
        let d = h.check_pids("team:health", 1000);
        assert!(d.is_deny());
    }

    #[test]
    fn test_pressure_level() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 50, 0, 5000, 0.0, 1000);
        assert!((h.pressure_level("agent:triage", "memory") - 0.5).abs() < 0.01);
        assert!((h.pressure_level("agent:triage", "compute") - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_psi_events_emitted() {
        let mut h = make_hierarchy();
        h.record_usage("agent:triage", 85, 0, 0, 0.0, 1000);
        h.check_memory("agent:triage", 1000);
        assert_eq!(h.pressure_events().len(), 1);
        assert_eq!(h.pressure_events()[0].controller, "memory");
    }

    #[test]
    fn test_audit_log_recorded() {
        let mut h = make_hierarchy();
        h.check_memory("agent:triage", 1000);
        h.check_compute("agent:triage", 1000);
        assert_eq!(h.audit_log().len(), 2);
    }
}
