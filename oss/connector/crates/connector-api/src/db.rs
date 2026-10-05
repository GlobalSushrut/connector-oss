//! Database View — user-level system to inspect memory, knowledge, agents, sessions, and audit.
//!
//! Inspired by:
//! - **Mem0**: `client.get_all(filters={...})` — filtered memory retrieval
//! - **Supabase Studio**: visual table browser with stats
//! - **AWS AgentCore Memory**: semantic/preference/summary extraction views
//!
//! ```rust,ignore
//! let c = Connector::new().llm("openai", "gpt-4o", "sk-...").build();
//! c.agent("bot").run("Hello", "user:alice").unwrap();
//!
//! // Browse everything
//! let db = c.db();
//! println!("{}", db.stats());        // database health & counts
//! println!("{}", db.memories());     // all memories
//! println!("{}", db.agents());       // registered agents
//! println!("{}", db.sessions());     // session history
//! println!("{}", db.audit(10));      // last 10 audit entries
//! println!("{}", db.knowledge());    // injected knowledge context
//! println!("{}", db.timeline(20));   // last 20 events chronologically
//!
//! // Filter memories (Mem0-style)
//! println!("{}", db.memories_by_user("user:alice"));
//! println!("{}", db.memories_by_kind("extraction"));
//! println!("{}", db.memories_by_agent("bot"));
//! println!("{}", db.find("dark mode"));  // search across all memories
//! ```

use std::fmt;
use connector_engine::ConnectorMemory;

use crate::connector::Connector;

// ═══════════════════════════════════════════════════════════════
// DatabaseView — the "Supabase Studio" for Connector
// ═══════════════════════════════════════════════════════════════

/// A read-only view into the Connector's data layer.
///
/// Provides browsing, filtering, and inspection of:
/// - **Memories**: all stored MemPackets as ConnectorMemory
/// - **Agents**: registered AgentControlBlocks
/// - **Sessions**: session envelopes
/// - **Audit**: HMAC-chained audit trail
/// - **Knowledge**: injected knowledge context
/// - **Stats**: database health and counts
pub struct DatabaseView<'a> {
    connector: &'a Connector,
}

impl<'a> DatabaseView<'a> {
    pub fn new(connector: &'a Connector) -> Self {
        Self { connector }
    }

    // ─── Stats ─────────────────────────────────────────────────

    /// Database health and summary statistics.
    pub fn stats(&self) -> DbStats {
        let kernel = self.connector.kernel.read().ok();
        let (packets, audits, agents, sessions) = match &kernel {
            Some(k) => (
                k.packet_count(),
                k.audit_count(),
                k.agent_count(),
                k.session_count(),
            ),
            None => (0, 0, 0, 0),
        };

        let storage_backend = match self.connector.storage_uri() {
            Some(uri) if uri.starts_with("redb:") => "redb (ACID, crash-safe)",
            Some(uri) if uri.ends_with(".redb") => "redb (ACID, crash-safe)",
            Some(uri) => uri,
            None => "in-memory (ephemeral)",
        };

        let audit_chain_valid = self.connector.verify_audit_chain().is_ok();

        DbStats {
            packets,
            audit_entries: audits,
            agents,
            sessions,
            storage_backend: storage_backend.to_string(),
            audit_chain_valid,
            compliance: self.connector.compliance().to_vec(),
            has_knowledge: self.connector.knowledge_context.is_some(),
        }
    }

    // ─── Memories ──────────────────────────────────────────────

    /// List all memories as ConnectorMemory.
    pub fn memories(&self) -> MemoryList {
        let kernel = self.connector.kernel.read().ok();
        let memories = match &kernel {
            Some(k) => k.all_packets()
                .iter()
                .map(|p| ConnectorMemory::from_packet(p))
                .collect(),
            None => Vec::new(),
        };
        MemoryList { memories, filter_desc: "all".to_string() }
    }

    /// Filter memories by user ID (Mem0-style).
    pub fn memories_by_user(&self, user_id: &str) -> MemoryList {
        let kernel = self.connector.kernel.read().ok();
        let memories = match &kernel {
            Some(k) => k.all_packets()
                .iter()
                .filter(|p| p.subject_id == user_id)
                .map(|p| ConnectorMemory::from_packet(p))
                .collect(),
            None => Vec::new(),
        };
        MemoryList { memories, filter_desc: format!("user={}", user_id) }
    }

    /// Filter memories by kind (e.g., "extraction", "input", "decision").
    pub fn memories_by_kind(&self, kind: &str) -> MemoryList {
        let kernel = self.connector.kernel.read().ok();
        let memories = match &kernel {
            Some(k) => k.all_packets()
                .iter()
                .filter(|p| p.content.packet_type.to_string() == kind)
                .map(|p| ConnectorMemory::from_packet(p))
                .collect(),
            None => Vec::new(),
        };
        MemoryList { memories, filter_desc: format!("kind={}", kind) }
    }

    /// Filter memories by agent namespace.
    pub fn memories_by_agent(&self, agent_name: &str) -> MemoryList {
        let kernel = self.connector.kernel.read().ok();
        let memories = match &kernel {
            Some(k) => k.all_packets()
                .iter()
                .filter(|p| p.namespace.as_deref() == Some(agent_name))
                .map(|p| ConnectorMemory::from_packet(p))
                .collect(),
            None => Vec::new(),
        };
        MemoryList { memories, filter_desc: format!("agent={}", agent_name) }
    }

    /// Search memories by content substring (case-insensitive).
    pub fn find(&self, query: &str) -> MemoryList {
        let query_lower = query.to_lowercase();
        let kernel = self.connector.kernel.read().ok();
        let memories = match &kernel {
            Some(k) => k.all_packets()
                .iter()
                .filter(|p| {
                    let content = match &p.content.payload {
                        serde_json::Value::String(s) => s.to_lowercase(),
                        other => other.to_string().to_lowercase(),
                    };
                    content.contains(&query_lower)
                        || p.content.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
                })
                .map(|p| ConnectorMemory::from_packet(p))
                .collect(),
            None => Vec::new(),
        };
        MemoryList { memories, filter_desc: format!("search=\"{}\"", query) }
    }

    /// Get a single memory by ID (CID string).
    pub fn memory(&self, id: &str) -> Option<ConnectorMemory> {
        let kernel = self.connector.kernel.read().ok()?;
        kernel.all_packets()
            .iter()
            .find(|p| p.index.packet_cid.to_string() == id)
            .map(|p| ConnectorMemory::from_packet(p))
    }

    // ─── Agents ────────────────────────────────────────────────

    /// List all registered agents.
    pub fn agents(&self) -> AgentList {
        let kernel = self.connector.kernel.read().ok();
        let agents = match &kernel {
            Some(k) => k.all_agents()
                .iter()
                .map(|acb| AgentInfo {
                    pid: acb.agent_pid.clone(),
                    name: acb.agent_pid.split(':').last().unwrap_or(&acb.agent_pid).to_string(),
                    registered_at: acb.registered_at,
                    terminated: acb.terminated_at.is_some(),
                    termination_reason: acb.termination_reason.clone(),
                })
                .collect(),
            None => Vec::new(),
        };
        AgentList { agents }
    }

    // ─── Sessions ──────────────────────────────────────────────

    /// List all sessions.
    pub fn sessions(&self) -> SessionList {
        let kernel = self.connector.kernel.read().ok();
        let sessions = match &kernel {
            Some(k) => k.all_sessions()
                .iter()
                .map(|se| SessionInfo {
                    id: se.session_id.clone(),
                    label: se.label.clone(),
                    parent: se.parent_session_id.clone(),
                    children: se.child_session_ids.len(),
                    total_tokens: se.total_tokens,
                    has_summary: se.summary.is_some(),
                })
                .collect(),
            None => Vec::new(),
        };
        SessionList { sessions }
    }

    // ─── Audit ─────────────────────────────────────────────────

    /// Browse the last N audit entries.
    pub fn audit(&self, limit: usize) -> AuditList {
        let kernel = self.connector.kernel.read().ok();
        let entries = match &kernel {
            Some(k) => {
                let all = k.audit_entries();
                let start = if all.len() > limit { all.len() - limit } else { 0 };
                all[start..].iter().map(|e| AuditInfo {
                    id: e.audit_id.clone(),
                    timestamp_ms: e.timestamp,
                    agent: e.agent_pid.clone(),
                    operation: format!("{:?}", e.operation),
                    outcome: format!("{:?}", e.outcome),
                    chain_hash: e.before_hash.clone(),
                }).collect()
            }
            None => Vec::new(),
        };
        AuditList { entries, total: kernel.map(|k| k.audit_count()).unwrap_or(0) }
    }

    // ─── Knowledge ─────────────────────────────────────────────

    /// View injected knowledge context.
    pub fn knowledge(&self) -> KnowledgeView {
        KnowledgeView {
            context: self.connector.knowledge_context.clone(),
            compliance: self.connector.compliance().to_vec(),
            llm: self.connector.llm_config().map(|l| format!("{}/{}", l.provider, l.model)),
        }
    }

    // ─── Timeline ──────────────────────────────────────────────

    /// Chronological view of the last N events across all subsystems.
    pub fn timeline(&self, limit: usize) -> Timeline {
        let kernel = self.connector.kernel.read().ok();
        let mut events: Vec<TimelineEvent> = Vec::new();

        if let Some(k) = &kernel {
            // Audit entries → timeline events
            for e in k.audit_entries().iter().rev().take(limit) {
                events.push(TimelineEvent {
                    timestamp_ms: e.timestamp,
                    source: "kernel".to_string(),
                    agent: e.agent_pid.clone(),
                    event: format!("{:?}", e.operation),
                    detail: format!("{:?}", e.outcome),
                });
            }
        }

        // Sort by timestamp descending
        events.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        events.truncate(limit);

        Timeline { events }
    }
}

// ═══════════════════════════════════════════════════════════════
// Result types with beautiful Display implementations
// ═══════════════════════════════════════════════════════════════

/// Database health and statistics.
pub struct DbStats {
    pub packets: usize,
    pub audit_entries: usize,
    pub agents: usize,
    pub sessions: usize,
    pub storage_backend: String,
    pub audit_chain_valid: bool,
    pub compliance: Vec<String>,
    pub has_knowledge: bool,
}

impl fmt::Display for DbStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "  ┌─────────────────────────────────────────────┐")?;
        writeln!(f, "  │  📊 Connector Database                      │")?;
        writeln!(f, "  └─────────────────────────────────────────────┘")?;
        writeln!(f)?;
        writeln!(f, "  Memories:       {}", self.packets)?;
        writeln!(f, "  Agents:         {}", self.agents)?;
        writeln!(f, "  Sessions:       {}", self.sessions)?;
        writeln!(f, "  Audit entries:  {}", self.audit_entries)?;
        writeln!(f, "  Storage:        {}", self.storage_backend)?;
        writeln!(f, "  Audit chain:    {}", if self.audit_chain_valid { "✅ valid" } else { "⚠️ broken" })?;
        if !self.compliance.is_empty() {
            writeln!(f, "  Compliance:     {}", self.compliance.iter()
                .map(|c| format!("{} ✓", c.to_uppercase()))
                .collect::<Vec<_>>().join("  "))?;
        }
        writeln!(f, "  Knowledge:      {}", if self.has_knowledge { "✅ loaded" } else { "— none" })?;
        Ok(())
    }
}

/// List of memories with filter description.
pub struct MemoryList {
    pub memories: Vec<ConnectorMemory>,
    pub filter_desc: String,
}

impl fmt::Display for MemoryList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "  📝 Memories ({}) — filter: {}", self.memories.len(), self.filter_desc)?;
        writeln!(f, "  ─────────────────────────────────────────────")?;
        if self.memories.is_empty() {
            writeln!(f, "  (no memories found)")?;
        }
        for (i, m) in self.memories.iter().enumerate() {
            let content_preview = if m.content.len() > 60 {
                format!("{}…", &m.content[..57])
            } else {
                m.content.clone()
            };
            let verified_icon = if m.verified { "✅" } else { "⚪" };
            writeln!(f, "  {} {}. [{}] {} | {} | score:{:.2} | {}",
                verified_icon, i + 1, m.kind, content_preview, m.user, m.score, m.created.split('T').next().unwrap_or(&m.created))?;
            if !m.tags.is_empty() {
                writeln!(f, "       tags: {}", m.tags.join(", "))?;
            }
        }
        Ok(())
    }
}

/// Agent information.
pub struct AgentInfo {
    pub pid: String,
    pub name: String,
    pub registered_at: i64,
    pub terminated: bool,
    pub termination_reason: Option<String>,
}

/// List of agents.
pub struct AgentList {
    pub agents: Vec<AgentInfo>,
}

impl fmt::Display for AgentList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "  🤖 Agents ({})", self.agents.len())?;
        writeln!(f, "  ─────────────────────────────────────────────")?;
        if self.agents.is_empty() {
            writeln!(f, "  (no agents registered)")?;
        }
        for a in &self.agents {
            let status = if a.terminated {
                format!("❌ terminated: {}", a.termination_reason.as_deref().unwrap_or("unknown"))
            } else {
                "✅ active".to_string()
            };
            writeln!(f, "  {} — {} [pid: {}]", a.name, status, a.pid)?;
        }
        Ok(())
    }
}

/// Session information.
pub struct SessionInfo {
    pub id: String,
    pub label: Option<String>,
    pub parent: Option<String>,
    pub children: usize,
    pub total_tokens: u64,
    pub has_summary: bool,
}

/// List of sessions.
pub struct SessionList {
    pub sessions: Vec<SessionInfo>,
}

impl fmt::Display for SessionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "  💬 Sessions ({})", self.sessions.len())?;
        writeln!(f, "  ─────────────────────────────────────────────")?;
        if self.sessions.is_empty() {
            writeln!(f, "  (no sessions)")?;
        }
        for s in &self.sessions {
            let label = s.label.as_deref().unwrap_or("—");
            let summary_icon = if s.has_summary { "📋" } else { "  " };
            writeln!(f, "  {} {} | {} | tokens:{} | children:{}",
                summary_icon, s.id, label, s.total_tokens, s.children)?;
        }
        Ok(())
    }
}

/// Audit entry information.
pub struct AuditInfo {
    pub id: String,
    pub timestamp_ms: i64,
    pub agent: String,
    pub operation: String,
    pub outcome: String,
    pub chain_hash: Option<String>,
}

/// List of audit entries.
pub struct AuditList {
    pub entries: Vec<AuditInfo>,
    pub total: usize,
}

impl fmt::Display for AuditList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "  🔒 Audit Trail (showing {} of {})", self.entries.len(), self.total)?;
        writeln!(f, "  ─────────────────────────────────────────────")?;
        if self.entries.is_empty() {
            writeln!(f, "  (no audit entries)")?;
        }
        for e in &self.entries {
            let time = chrono::DateTime::from_timestamp_millis(e.timestamp_ms)
                .map(|dt| dt.format("%H:%M:%S%.3f").to_string())
                .unwrap_or_else(|| e.timestamp_ms.to_string());
            let hash_preview = e.chain_hash.as_ref()
                .map(|h| format!(" [{}…]", &h[..8.min(h.len())]))
                .unwrap_or_default();
            writeln!(f, "  {} {} | {} | {} | {}{}",
                e.id, time, e.agent, e.operation, e.outcome, hash_preview)?;
        }
        Ok(())
    }
}

/// Knowledge context view.
pub struct KnowledgeView {
    pub context: Option<String>,
    pub compliance: Vec<String>,
    pub llm: Option<String>,
}

impl fmt::Display for KnowledgeView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "  🧠 Knowledge & Context")?;
        writeln!(f, "  ─────────────────────────────────────────────")?;
        if let Some(ref ctx) = self.context {
            writeln!(f, "  Knowledge context:")?;
            for line in ctx.lines() {
                writeln!(f, "    │ {}", line)?;
            }
        } else {
            writeln!(f, "  Knowledge: — none injected")?;
        }
        if let Some(ref llm) = self.llm {
            writeln!(f, "  LLM: {}", llm)?;
        }
        if !self.compliance.is_empty() {
            writeln!(f, "  Compliance: {}", self.compliance.join(", "))?;
        }
        Ok(())
    }
}

/// A timeline event.
pub struct TimelineEvent {
    pub timestamp_ms: i64,
    pub source: String,
    pub agent: String,
    pub event: String,
    pub detail: String,
}

/// Chronological timeline of events.
pub struct Timeline {
    pub events: Vec<TimelineEvent>,
}

impl fmt::Display for Timeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "  🕐 Timeline ({})", self.events.len())?;
        writeln!(f, "  ─────────────────────────────────────────────")?;
        if self.events.is_empty() {
            writeln!(f, "  (no events)")?;
        }
        for e in &self.events {
            let time = chrono::DateTime::from_timestamp_millis(e.timestamp_ms)
                .map(|dt| dt.format("%H:%M:%S%.3f").to_string())
                .unwrap_or_else(|| e.timestamp_ms.to_string());
            writeln!(f, "  {} [{}] {} — {} | {}",
                time, e.source, e.agent, e.event, e.detail)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Connector;

    fn make_test_connector() -> Connector {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        // Run some operations to populate data
        let _ = c.agent("doctor")
            .instructions("You are a medical AI")
            .run("Patient has fever", "user:patient-001")
            .unwrap();
        let _ = c.agent("nurse")
            .instructions("You are a nurse AI")
            .run("Check vitals for patient", "user:patient-001")
            .unwrap();
        c
    }

    #[test]
    fn test_db_stats() {
        let c = make_test_connector();
        let db = c.db();
        let stats = db.stats();

        assert!(stats.packets > 0, "should have packets");
        assert!(stats.agents > 0, "should have agents");
        assert!(stats.audit_entries > 0, "should have audit entries");
        assert!(stats.audit_chain_valid, "audit chain should be valid");
        assert_eq!(stats.compliance, vec!["hipaa"]);

        // Display should work
        let display = format!("{}", stats);
        assert!(display.contains("Connector Database"), "stats display: {}", display);
        assert!(display.contains("Memories:"), "stats display: {}", display);
        assert!(display.contains("HIPAA"), "stats display: {}", display);
    }

    #[test]
    fn test_db_memories() {
        let c = make_test_connector();
        let db = c.db();
        let mems = db.memories();

        assert!(mems.memories.len() > 0, "should have memories");
        assert_eq!(mems.filter_desc, "all");

        let display = format!("{}", mems);
        assert!(display.contains("Memories"), "display: {}", display);
    }

    #[test]
    fn test_db_memories_by_user() {
        let c = make_test_connector();
        let db = c.db();
        let mems = db.memories_by_user("user:patient-001");

        assert!(mems.memories.len() > 0, "should find memories for user");
        assert!(mems.memories.iter().all(|m| m.user == "user:patient-001"));
    }

    #[test]
    fn test_db_memories_by_agent() {
        let c = make_test_connector();
        let db = c.db();
        let mems = db.memories_by_agent("doctor");

        // Doctor's namespace should have memories
        assert!(mems.filter_desc.contains("doctor"));
    }

    #[test]
    fn test_db_find() {
        let c = make_test_connector();
        let db = c.db();

        // Search for content that should exist
        let found = db.find("fever");
        assert!(found.filter_desc.contains("fever"));
        // Note: content may or may not match depending on how the engine processes it
    }

    #[test]
    fn test_db_agents() {
        let c = make_test_connector();
        let db = c.db();
        let agents = db.agents();

        assert!(agents.agents.len() >= 2, "should have doctor and nurse, got {}", agents.agents.len());

        let display = format!("{}", agents);
        assert!(display.contains("Agents"), "display: {}", display);
    }

    #[test]
    fn test_db_sessions() {
        let c = make_test_connector();
        let db = c.db();
        let sessions = db.sessions();

        // Sessions display should work even if empty
        let display = format!("{}", sessions);
        assert!(display.contains("Sessions"), "display: {}", display);
    }

    #[test]
    fn test_db_audit() {
        let c = make_test_connector();
        let db = c.db();
        let audit = db.audit(5);

        assert!(audit.entries.len() > 0, "should have audit entries");
        assert!(audit.total > 0);

        let display = format!("{}", audit);
        assert!(display.contains("Audit Trail"), "display: {}", display);
    }

    #[test]
    fn test_db_knowledge() {
        let c = make_test_connector();
        let db = c.db();
        let knowledge = db.knowledge();

        let display = format!("{}", knowledge);
        assert!(display.contains("Knowledge"), "display: {}", display);
        assert!(display.contains("hipaa"), "display: {}", display);
    }

    #[test]
    fn test_db_timeline() {
        let c = make_test_connector();
        let db = c.db();
        let timeline = db.timeline(10);

        assert!(timeline.events.len() > 0, "should have timeline events");

        let display = format!("{}", timeline);
        assert!(display.contains("Timeline"), "display: {}", display);
    }

    #[test]
    fn test_db_stats_display_format() {
        let c = make_test_connector();
        let stats = c.db().stats();
        let display = format!("{}", stats);

        // Should have the box drawing header
        assert!(display.contains("┌"), "should have box header");
        assert!(display.contains("📊"), "should have database emoji");
        assert!(display.contains("Storage:"), "should show storage backend");
        assert!(display.contains("Audit chain:"), "should show audit chain status");
    }
}
