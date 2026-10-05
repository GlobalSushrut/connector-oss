//! Kernel Integration — Bridge to Memory Kernel and Books
//!
//! Following Connector patterns: SOE connects to the kernel for authoritative data.

use super::document::*;
use super::tiers::{TrustTier, TierVerification};
use super::receipt::TimeContext;
use serde::{Deserialize, Serialize};

/// Source of surface data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSource {
    /// Direct kernel syscall (T0)
    Kernel,
    /// Engine store (T1)
    EngineStore,
    /// Books journal (T1)
    BooksJournal,
    /// Computed/derived (T2)
    Computed,
    /// Cache (T3)
    Cache,
    /// Mock/stub (T3)
    Mock,
}

impl DataSource {
    pub fn trust_tier(&self) -> TrustTier {
        match self {
            Self::Kernel => TrustTier::T0Notarized,
            Self::EngineStore | Self::BooksJournal => TrustTier::T1Recorded,
            Self::Computed => TrustTier::T2Derived,
            Self::Cache | Self::Mock => TrustTier::T3Rendered,
        }
    }
}

/// Kernel query for surface data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelQuery {
    pub subject_id: String,
    pub query_type: KernelQueryType,
    pub time_context: Option<TimeContext>,
    pub namespace: Option<String>,
    pub limit: Option<usize>,
}

impl KernelQuery {
    pub fn new(query_type: KernelQueryType, subject_id: &str) -> Self {
        Self {
            subject_id: subject_id.to_string(),
            query_type,
            time_context: None,
            namespace: None,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelQueryType {
    AgentState,
    AgentHealth,
    AgentTrace,
    MemoryPackets,
    MemorySession,
    AuditEntries,
    JournalEntries,
    PolicyChecks,
    EvidenceChain,
    KnowledgeGraph,
    /// BUG-31: Compliance posture from compliance engine
    CompliancePosture,
}

/// Result from kernel query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelResult {
    pub source: DataSource,
    pub tier: TierVerification,
    pub data: KernelData,
    pub timestamp: i64,
    pub chain_position: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KernelData {
    AgentState {
        pid: String,
        status: String,
        uptime_ms: u64,
        /// Legacy byte estimate when API exposes only tokens; prefer `memory_packets` for live agents.
        memory_used: u64,
        /// Authoritative packet count from `/memory/packets` when available.
        #[serde(default)]
        memory_packets: u64,
        tool_calls: u64,
        last_activity: i64,
        total_cost_usd: f64,
        total_tokens: u64,
        /// Capability identifiers from the agent manifest, e.g. ["memory.read", "tool.call"]
        #[serde(default)]
        capabilities: Vec<String>,
    },
    AgentHealth {
        cpu_percent: f64,
        /// Whether cpu_percent came from a real metric or is a placeholder zero
        cpu_available: bool,
        memory_mb: f64,
        response_time_ms: u64,
        /// Whether `response_time_ms` came from the API (else display as N/A, not "0 ms")
        #[serde(default)]
        latency_available: bool,
        error_rate: f64,
        health_score: u8,
    },
    AuditEntries(Vec<AuditEntry>),
    JournalEntries(Vec<JournalEntry>),
    MemoryPackets(Vec<PacketSummary>),
    EvidenceChain {
        root_hash: String,
        chain_length: u64,
        verified: bool,
        receipts: Vec<String>,
    },
    CompliancePosture {
        compliant: bool,
        partial: bool,
        framework: String,
        findings_count: u64,
    },
    /// Returned when the endpoint is not implemented or the data source does not exist.
    /// The `reason` field carries the human-readable explanation of why data is missing.
    Unavailable {
        reason: String,
    },
    Empty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub operation: String,
    pub actor: String,
    pub target: String,
    pub outcome: String,
    pub hmac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub timestamp: i64,
    pub action: String,
    pub actor: String,
    pub target: String,
    pub outcome: String,
    pub quantity: Option<f64>,
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub cid: String,
    pub packet_type: String,
    pub timestamp: i64,
    pub preview: String,
    pub tier: String,
}

/// Kernel bridge for fetching authoritative data
pub struct KernelBridge {
    source: DataSource,
    /// Base URL of the platform API, e.g. "http://localhost:9091"
    /// When set, `query()` will call real endpoints instead of returning mock data.
    api_base: Option<String>,
}

impl Default for KernelBridge {
    fn default() -> Self { Self::mock() }
}

impl KernelBridge {
    /// Mock bridge — returns static placeholder data. Safe for unit tests only.
    pub fn mock() -> Self {
        #[cfg(not(test))]
        eprintln!("[SOE] WARNING: KernelBridge running in mock mode — output is synthetic, not live API data");
        Self { source: DataSource::Mock, api_base: None }
    }

    /// Live bridge — queries real platform API endpoints.
    /// Falls back to `KernelData::Empty` (not fake data) when the agent is not found or
    /// the API is unreachable.
    pub fn live(api_base: &str) -> Self {
        Self {
            source: DataSource::EngineStore,
            api_base: Some(api_base.trim_end_matches('/').to_string()),
        }
    }

    pub fn kernel() -> Self {
        Self { source: DataSource::Kernel, api_base: None }
    }

    fn live_http_client() -> Option<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()
    }

    /// GET JSON under `/api/v1/{path}`; retry with `agent_` prefix when `pid` in path fails.
    fn fetch_v1_with_agent_pid_fallback(
        client: &reqwest::blocking::Client,
        api_base: &str,
        pid: &str,
        build_path: impl Fn(&str) -> String,
    ) -> Option<serde_json::Value> {
        let base = api_base.trim_end_matches('/');
        let attempt = |p: &str| -> Option<serde_json::Value> {
            let path = build_path(p);
            let url = format!("{}/api/v1/{}", base, path);
            let v: serde_json::Value = client.get(&url).send().ok()?.json().ok()?;
            if v.get("error").is_some() { None } else { Some(v) }
        };
        attempt(pid).or_else(|| {
            if pid.starts_with("agent_") {
                None
            } else {
                attempt(&format!("agent_{}", pid))
            }
        })
    }

    /// GET `/api/v1/agents/{pid}` with bare-id → `agent_` retry (BUG-SOE-01 / BUG-SOE-14).
    fn fetch_agent_json(
        client: &reqwest::blocking::Client,
        api_base: &str,
        pid: &str,
    ) -> Option<serde_json::Value> {
        Self::fetch_v1_with_agent_pid_fallback(client, api_base, pid, |p| format!("agents/{}", p))
    }

    /// Attempt to fetch real data from the platform API.
    /// Returns `None` when the endpoint is unreachable, the agent does not exist, or
    /// the response cannot be parsed — the caller falls back gracefully.
    fn query_live(&self, api_base: &str, query: &KernelQuery) -> Option<KernelData> {
        let client = Self::live_http_client()?;
        let pid = &query.subject_id;

        // Decision IDs (dec_...) → disputes API, not the agent endpoint
        if pid.starts_with("dec_") && matches!(query.query_type, KernelQueryType::AgentState | KernelQueryType::AgentHealth | KernelQueryType::EvidenceChain) {
            return self.query_decision_record(&client, api_base, pid);
        }

        match query.query_type {
            KernelQueryType::AgentState | KernelQueryType::AgentHealth => {
                let resp = Self::fetch_agent_json(&client, api_base, pid)?;

                match query.query_type {
                    KernelQueryType::AgentState => {
                        let api_pid = resp
                            .get("pid")
                            .and_then(|v| v.as_str())
                            .unwrap_or(pid)
                            .to_string();
                        let uptime_ms = resp.get("registered_at")
                            .and_then(|v| v.as_str())
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| {
                                let now = chrono::Utc::now().timestamp_millis();
                                (now - dt.timestamp_millis()).max(0) as u64
                            })
                            .unwrap_or(0);
                        let memory_packets = resp
                            .pointer("/memory/packets")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let memory_used = resp
                            .pointer("/memory/used_bytes")
                            .and_then(|v| v.as_u64())
                            .or_else(|| {
                                resp.pointer("/memory/used_tokens")
                                    .and_then(|v| v.as_u64())
                                    .map(|t| t.saturating_mul(4))
                            })
                            .unwrap_or(0);
                        let tool_calls = resp
                            .pointer("/operations/total")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let status = resp
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let total_cost_usd = resp
                            .pointer("/cost/total_cost_usd")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let total_tokens = resp
                            .pointer("/cost/total_tokens_consumed")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let last_activity = resp
                            .get("last_active_at")
                            .or_else(|| resp.get("last_activity"))
                            .or_else(|| resp.get("updated_at"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.timestamp_millis())
                            .or_else(|| {
                                resp.get("last_activity_ms").and_then(|v| v.as_i64())
                            })
                            .unwrap_or(0);
                        let mut capabilities = resp
                            .get("capabilities")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|c| c.as_str().map(|s| s.to_string())).collect::<Vec<_>>())
                            .unwrap_or_default();
                        if capabilities.is_empty() {
                            let n = resp.pointer("/operations/tool_bindings").and_then(|v| v.as_u64()).unwrap_or(0);
                            if n > 0 {
                                capabilities.push(format!("{} tool binding(s) — see GET /agents/:pid capabilities", n));
                            }
                        }
                        Some(KernelData::AgentState {
                            pid: api_pid,
                            status,
                            uptime_ms,
                            memory_used,
                            memory_packets,
                            tool_calls,
                            last_activity,
                            total_cost_usd,
                            total_tokens,
                            capabilities,
                        })
                    }
                    KernelQueryType::AgentHealth => {
                        let success_rate = resp
                            .pointer("/operations/success_rate")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(100.0);
                        let error_rate = ((100.0 - success_rate) / 100.0).clamp(0.0, 1.0);
                        let budget_pct = resp
                            .pointer("/cost/budget_pct")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let health_score: u8 = if error_rate < 0.05 && budget_pct < 80.0 { 95 }
                            else if error_rate < 0.20 && budget_pct < 95.0 { 70 }
                            else { 40 };
                        // BUG-14: Real cpu_percent from metrics API field
                        let cpu_raw = resp
                            .get("cpu_percent")
                            .or_else(|| resp.pointer("/metrics/cpu_percent"))
                            .or_else(|| resp.pointer("/health/cpu_pct"))
                            .and_then(|v| v.as_f64());
                        let cpu_available = cpu_raw.is_some();
                        let cpu_percent = cpu_raw.unwrap_or(0.0);
                        // BUG-14: Real response_time_ms from latency field
                        let latency_raw = resp
                            .get("latency_p95_ms")
                            .or_else(|| resp.pointer("/metrics/latency_p95_ms"))
                            .or_else(|| resp.get("response_time_ms"))
                            .and_then(|v| v.as_u64());
                        let latency_available = latency_raw.is_some();
                        let response_time_ms = latency_raw.unwrap_or(0);
                        // BUG-17: Prefer real memory_bytes from API; fall back to token-derived MB
                        let memory_mb = resp
                            .pointer("/memory/used_bytes")
                            .or_else(|| resp.get("memory_bytes"))
                            .and_then(|v| v.as_f64())
                            .map(|b| b / 1_000_000.0)
                            .unwrap_or_else(|| {
                                resp.pointer("/memory/used_tokens")
                                    .and_then(|v| v.as_f64())
                                    .unwrap_or(0.0)
                                    * 4.0 / 1_000_000.0
                            });
                        Some(KernelData::AgentHealth {
                            cpu_percent,
                            cpu_available,
                            memory_mb,
                            response_time_ms,
                            latency_available,
                            error_rate,
                            health_score,
                        })
                    }
                    _ => None,
                }
            }

            KernelQueryType::AuditEntries => {
                let limit = query.limit.unwrap_or(20) as usize;
                let resp = Self::fetch_v1_with_agent_pid_fallback(&client, api_base, pid, |p| {
                    format!("agents/{}/audit/receipts?limit={}", p, limit)
                })?;
                let entries = resp
                    .get("receipts")
                    .or_else(|| resp.get("entries"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter().take(limit).filter_map(|e| {
                            Some(AuditEntry {
                                timestamp: e.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0),
                                operation: e.get("operation").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                                actor: pid.clone(),
                                target: e.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                outcome: e.get("outcome").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                hmac: e.get("hmac").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            })
                        }).collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Some(KernelData::AuditEntries(entries))
            }

            KernelQueryType::EvidenceChain => {
                let resp = Self::fetch_v1_with_agent_pid_fallback(&client, api_base, pid, |p| {
                    format!("agents/{}/audit/receipts", p)
                })?;
                let count = resp.get("total").and_then(|v| v.as_u64())
                    .or_else(|| resp.get("receipts").and_then(|v| v.as_array()).map(|a| a.len() as u64))
                    .unwrap_or(0);
                let root_hash = resp.get("root_hash")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let verified = resp.get("verified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // BUG-24: parse receipts as strings OR as objects with hash/cid fields
                let receipts = resp.get("receipts")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|r| {
                        if let Some(s) = r.as_str() {
                            Some(s.to_string())
                        } else {
                            r.get("hash").or_else(|| r.get("cid")).or_else(|| r.get("id"))
                                .and_then(|v| v.as_str()).map(|s| s.to_string())
                        }
                    }).collect::<Vec<_>>())
                    .unwrap_or_default();
                Some(KernelData::EvidenceChain {
                    root_hash,
                    chain_length: count,
                    verified,
                    receipts,
                })
            }

            KernelQueryType::JournalEntries => {
                let resp = Self::fetch_v1_with_agent_pid_fallback(&client, api_base, pid, |p| {
                    format!("history/agents/{}/timeline", p)
                })?;
                let entries = resp
                    .get("events")
                    .or_else(|| resp.get("timeline"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter().take(20).filter_map(|e| {
                            Some(JournalEntry {
                                timestamp: e.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0),
                                action: e.get("event_type").or_else(|| e.get("action"))
                                    .and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                                actor: pid.clone(),
                                target: e.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                outcome: e.get("outcome").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                quantity: e.get("value").and_then(|v| v.as_f64()),
                                unit: e.get("unit").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            })
                        }).collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Some(KernelData::JournalEntries(entries))
            }

            KernelQueryType::AgentTrace => {
                let resp_opt = Self::fetch_v1_with_agent_pid_fallback(&client, api_base, pid, |p| {
                    format!("debug/agents/{}/tool-trace", p)
                });
                let mut entries = resp_opt
                    .as_ref()
                    .and_then(|resp| {
                        resp.get("trace")
                            .or_else(|| resp.get("events"))
                            .or_else(|| resp.get("calls"))
                            .and_then(|v| v.as_array())
                    })
                    .map(|arr| {
                        arr.iter().take(50).filter_map(|e| {
                            Some(AuditEntry {
                                timestamp: e.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0),
                                operation: e.get("tool").or_else(|| e.get("operation"))
                                    .and_then(|v| v.as_str()).unwrap_or("tool.call").to_string(),
                                actor: pid.clone(),
                                target: e.get("target").or_else(|| e.get("input"))
                                    .and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                outcome: e.get("outcome").or_else(|| e.get("result"))
                                    .and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                hmac: e.get("signature").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            })
                        }).collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if entries.is_empty() {
                    // Tool-trace missing or empty — use audit receipts as trace evidence
                    if let Some(resp2) = Self::fetch_v1_with_agent_pid_fallback(&client, api_base, pid, |p| {
                        format!("agents/{}/audit/receipts", p)
                    }) {
                        entries = resp2
                            .get("receipts")
                            .or_else(|| resp2.get("entries"))
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().take(50).filter_map(|e| {
                                Some(AuditEntry {
                                    timestamp: e.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0),
                                    operation: e.get("operation").and_then(|v| v.as_str()).unwrap_or("receipt").to_string(),
                                    actor: pid.clone(),
                                    target: e.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    outcome: e.get("outcome").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    hmac: e.get("hmac").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                })
                            }).collect::<Vec<_>>())
                            .unwrap_or_default();
                    }
                }
                Some(KernelData::AuditEntries(entries))
            }

            KernelQueryType::CompliancePosture => {
                let resp = Self::fetch_v1_with_agent_pid_fallback(&client, api_base, pid, |p| {
                    format!("compliance/agents/{}/posture", p)
                })?;
                let compliant = resp.get("compliant").and_then(|v| v.as_bool()).unwrap_or(false);
                let partial = resp.get("partial").and_then(|v| v.as_bool()).unwrap_or(false);
                let findings_count = resp.get("findings_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let framework = resp.get("framework").and_then(|v| v.as_str()).unwrap_or("security-baseline").to_string();
                Some(KernelData::CompliancePosture {
                    compliant,
                    partial,
                    framework,
                    findings_count,
                })
            }

            KernelQueryType::MemoryPackets => {
                let resp = Self::fetch_v1_with_agent_pid_fallback(&client, api_base, pid, |p| {
                    format!("agents/{}/memory", p)
                })?;
                let packets = resp
                    .get("packets")
                    .or_else(|| resp.get("entries"))
                    .or_else(|| resp.get("items"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter().take(20).filter_map(|e| {
                            Some(PacketSummary {
                                cid: e.get("cid").or_else(|| e.get("hash")).or_else(|| e.get("id"))
                                    .and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                packet_type: e.get("kind").or_else(|| e.get("type"))
                                    .and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                                timestamp: e.get("created_at").or_else(|| e.get("timestamp"))
                                    .and_then(|v| v.as_i64()).unwrap_or(0),
                                preview: e.get("key").or_else(|| e.get("preview")).or_else(|| e.get("namespace"))
                                    .and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                tier: e.get("tier").and_then(|v| v.as_str()).unwrap_or("T1").to_string(),
                            })
                        }).collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Some(KernelData::MemoryPackets(packets))
            }

            _ => None,
        }
    }

    /// Fetch a decision record by ID from the disputes API.
    fn query_decision_record(&self, client: &reqwest::blocking::Client, api_base: &str, decision_id: &str) -> Option<KernelData> {
        // GET /api/v1/disputes/decisions — list and find matching record
        let url = format!("{}/api/v1/disputes/decisions", api_base);
        let resp: serde_json::Value = client.get(&url).send().ok()?.json().ok()?;
        if resp.get("error").is_some() { return None; }

        // Search the list for the matching decision_id
        let record = resp
            .get("decisions")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find(|d| {
                    d.get("decision_id").and_then(|v| v.as_str()) == Some(decision_id)
                })
            })
            .cloned();

        let record = if let Some(r) = record {
            r
        } else {
            // Try the report endpoint as a fallback
            let report_url = format!("{}/api/v1/disputes/{}/report", api_base, decision_id);
            let rep: serde_json::Value = client.get(&report_url).send().ok()?.json().ok()?;
            rep.get("report").cloned().unwrap_or(rep)
        };

        let outcome = record
            .get("outcome")
            .or_else(|| record.get("action"))
            .and_then(|v| v.as_str())
            .unwrap_or("recorded")
            .to_string();
        let agent_pid = record
            .get("agent_pid")
            .and_then(|v| v.as_str())
            .unwrap_or(decision_id)
            .to_string();
        let action = record
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let target = record
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Build a status string that reflects what actually happened
        let status = if outcome == "approved" || outcome == "allowed" {
            format!("decision:allowed | agent={} | action={} target={}", agent_pid, action, target)
        } else if outcome.contains("block") || outcome.contains("deni") || outcome.contains("reject") {
            format!("decision:blocked | agent={} | action={} target={}", agent_pid, action, target)
        } else {
            format!("decision:{} | agent={}", outcome, agent_pid)
        };
        let age_ms = record
            .get("recorded_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| (chrono::Utc::now().timestamp_millis() - dt.timestamp_millis()).max(0) as u64)
            .unwrap_or(0);
        // EvidenceChain query: return verified if the record exists
        Some(KernelData::AgentState {
            pid: decision_id.to_string(),
            status,
            uptime_ms: age_ms,
            memory_used: 0,
            memory_packets: 0,
            tool_calls: 1,
            last_activity: chrono::Utc::now().timestamp_millis(),
            total_cost_usd: 0.0,
            total_tokens: 0,
            capabilities: vec![],
        })
    }

    /// Query kernel for surface data.
    ///
    /// When `api_base` is configured (live bridge), the real platform API is called.
    /// On failure the result is `KernelData::Empty` — no fake values are returned.
    /// When running as a mock bridge (unit tests) the static placeholder data is returned.
    pub fn query(&self, query: KernelQuery) -> KernelResult {
        // Live path: call real API
        if let Some(api_base) = &self.api_base {
            let data = self.query_live(api_base, &query).unwrap_or(KernelData::Empty);
            return KernelResult {
                source: DataSource::EngineStore,
                tier: TierVerification::t1_recorded(),
                data,
                timestamp: chrono::Utc::now().timestamp_millis(),
                chain_position: None,
            };
        }

        // Mock path — only used for unit tests
        let data = match query.query_type {
            KernelQueryType::AgentState => KernelData::AgentState {
                pid: query.subject_id.clone(),
                status: "mock".into(),
                uptime_ms: 0,
                capabilities: vec!["memory.read".into(), "tool.call".into(), "policy.enforce".into()],
                memory_used: 0,
                memory_packets: 0,
                tool_calls: 0,
                last_activity: chrono::Utc::now().timestamp_millis(),
                total_cost_usd: 0.0,
                total_tokens: 0,
            },
            KernelQueryType::AgentHealth => KernelData::AgentHealth {
                cpu_percent: 0.0,
                cpu_available: false,
                memory_mb: 0.0,
                response_time_ms: 0,
                latency_available: false,
                error_rate: 0.0,
                health_score: 0,
            },
            KernelQueryType::AuditEntries => KernelData::AuditEntries(vec![]),
            KernelQueryType::JournalEntries => KernelData::JournalEntries(vec![]),
            KernelQueryType::EvidenceChain => KernelData::EvidenceChain {
                root_hash: "sha256:mock".into(),
                chain_length: 0,
                verified: false,
                receipts: vec![],
            },
            KernelQueryType::CompliancePosture => KernelData::Unavailable {
                reason: "Compliance posture endpoint not available in mock mode".into(),
            },
            KernelQueryType::MemoryPackets => KernelData::MemoryPackets(vec![]),
            _ => KernelData::Empty,
        };

        KernelResult {
            source: self.source,
            tier: TierVerification::t3_rendered(),
            data,
            timestamp: chrono::Utc::now().timestamp_millis(),
            chain_position: None,
        }
    }

    /// Convert kernel result to surface sections
    pub fn to_sections(&self, result: &KernelResult) -> Vec<SurfaceSection> {
        match &result.data {
            KernelData::AgentState { pid, status, uptime_ms, memory_used, tool_calls, .. } => {
                vec![SurfaceSection {
                    title: "Agent State".into(),
                    kind: SectionKind::StatsGrid,
                    content: SectionContent::Stats(vec![
                        StatItem { label: "PID".into(), value: pid.clone(), link: None },
                        StatItem { label: "Status".into(), value: status.clone(), link: None },
                        StatItem { label: "Uptime".into(), value: format!("{}h", uptime_ms / 3_600_000), link: None },
                        StatItem { label: "Memory".into(), value: format!("{} MB", memory_used / 1_000_000), link: None },
                        StatItem { label: "Tool Calls".into(), value: tool_calls.to_string(), link: None },
                    ]),
                    collapsed: false,
                }]
            },
            KernelData::AgentHealth { cpu_percent, cpu_available, memory_mb, response_time_ms, latency_available, error_rate, health_score } => {
                let cpu_str = if *cpu_available { format!("{:.1}%", cpu_percent) } else { "N/A".into() };
                let rt_str = if *latency_available { format!("{} ms", response_time_ms) } else { "N/A".into() };
                vec![SurfaceSection {
                    title: "Health Metrics".into(),
                    kind: SectionKind::StatsGrid,
                    content: SectionContent::Stats(vec![
                        StatItem { label: "CPU".into(), value: cpu_str, link: None },
                        StatItem { label: "Memory".into(), value: format!("{:.0} MB", memory_mb), link: None },
                        StatItem { label: "Response Time".into(), value: rt_str, link: None },
                        StatItem { label: "Error Rate".into(), value: format!("{:.1}%", error_rate), link: None },
                        StatItem { label: "Health Score".into(), value: format!("{}/100", health_score), link: None },
                    ]),
                    collapsed: false,
                }]
            },
            KernelData::AuditEntries(entries) => {
                vec![SurfaceSection {
                    title: "Audit Trail".into(),
                    kind: SectionKind::Timeline,
                    content: SectionContent::Timeline(entries.iter().map(|e| TimelineEvent {
                        timestamp: chrono::DateTime::from_timestamp_millis(e.timestamp)
                            .map(|dt| dt.format("%H:%M:%S").to_string())
                            .unwrap_or_default(),
                        event_type: e.operation.clone(),
                        message: format!("{} → {} ({})", e.actor, e.target, e.outcome),
                        severity: match e.outcome.as_str() {
                            "success" | "ok" | "approved" | "allowed" | "passed" | "completed" => Severity::Ok,
                            "denied" | "blocked" | "rejected" => Severity::Risk,
                            "failed" | "error" | "tampered" => Severity::Critical,
                            _ => Severity::Warn,
                        },
                        link: None,
                    }).collect()),
                    collapsed: false,
                }]
            },
            KernelData::EvidenceChain { root_hash, chain_length, verified, receipts: _ } => {
                vec![SurfaceSection {
                    title: "Evidence Chain".into(),
                    kind: SectionKind::Evidence,
                    content: SectionContent::Evidence(vec![
                        EvidenceItem {
                            evidence_type: "Root Hash".into(),
                            cid: root_hash.clone(),
                            verified: *verified,
                            link: ResourceLink::verify(ResourceKind::Proof, root_hash),
                        },
                        EvidenceItem {
                            evidence_type: "Chain Length".into(),
                            cid: chain_length.to_string(),
                            verified: true,
                            link: ResourceLink::verify(ResourceKind::Proof, &chain_length.to_string()),
                        },
                    ]),
                    collapsed: false,
                }]
            },
            KernelData::JournalEntries(entries) => {
                vec![SurfaceSection {
                    title: "Journal".into(),
                    kind: SectionKind::Timeline,
                    content: SectionContent::Timeline(entries.iter().map(|e| TimelineEvent {
                        timestamp: chrono::DateTime::from_timestamp_millis(e.timestamp)
                            .map(|dt| dt.format("%H:%M:%S").to_string())
                            .unwrap_or_default(),
                        event_type: e.action.clone(),
                        message: format!("{} → {} ({})", e.actor, e.target, e.outcome),
                        severity: match e.outcome.as_str() {
                            "success" | "ok" | "completed" => Severity::Ok,
                            "fail" | "failed" | "error" => Severity::Critical,
                            "blocked" | "denied" => Severity::Risk,
                            _ => Severity::Info,
                        },
                        link: None,
                    }).collect()),
                    collapsed: false,
                }]
            },
            KernelData::MemoryPackets(packets) => {
                vec![SurfaceSection {
                    title: "Memory Packets".into(),
                    kind: SectionKind::Timeline,
                    content: SectionContent::Timeline(packets.iter().map(|p| TimelineEvent {
                        timestamp: chrono::DateTime::from_timestamp_millis(p.timestamp)
                            .map(|dt| dt.format("%H:%M:%S").to_string())
                            .unwrap_or_default(),
                        event_type: p.packet_type.clone(),
                        message: format!("{} [{}] cid={}", p.preview, p.tier, &p.cid[..p.cid.len().min(16)]),
                        severity: Severity::Info,
                        link: None,
                    }).collect()),
                    collapsed: false,
                }]
            },
            KernelData::CompliancePosture { compliant, partial, framework, findings_count } => {
                let status = if *compliant { "Compliant" } else if *partial { "Partial" } else { "Non-Compliant" };
                vec![SurfaceSection {
                    title: "Compliance Posture".into(),
                    kind: SectionKind::StatsGrid,
                    content: SectionContent::Stats(vec![
                        StatItem { label: "Framework".into(), value: framework.clone(), link: None },
                        StatItem { label: "Status".into(), value: status.into(), link: None },
                        StatItem { label: "Findings".into(), value: findings_count.to_string(), link: None },
                    ]),
                    collapsed: false,
                }]
            },
            KernelData::Unavailable { reason } => {
                vec![SurfaceSection {
                    title: "Data Unavailable".into(),
                    kind: SectionKind::Narrative,
                    content: SectionContent::Narrative(reason.clone()),
                    collapsed: false,
                }]
            },
            KernelData::Empty => {
                vec![SurfaceSection {
                    title: "Data Unavailable".into(),
                    kind: SectionKind::Narrative,
                    content: SectionContent::Narrative("No data returned — API may be unreachable or agent not found".into()),
                    collapsed: false,
                }]
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_bridge() {
        let bridge = KernelBridge::mock();
        let query = KernelQuery {
            subject_id: "agent-001".into(),
            query_type: KernelQueryType::AgentState,
            time_context: None,
            namespace: None,
            limit: None,
        };
        let result = bridge.query(query);
        assert!(matches!(result.data, KernelData::AgentState { .. }));
    }

    #[test]
    fn test_to_sections() {
        let bridge = KernelBridge::mock();
        let query = KernelQuery {
            subject_id: "agent-001".into(),
            query_type: KernelQueryType::AgentHealth,
            time_context: None,
            namespace: None,
            limit: None,
        };
        let result = bridge.query(query);
        let sections = bridge.to_sections(&result);
        assert!(!sections.is_empty());
    }
}
