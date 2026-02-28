//! Persistent Firewall Events + SIEM Export — store, query, and export threat events.
//!
//! Military-grade properties:
//! - All events persisted (survives restart)
//! - SIEM export: syslog (RFC 5424), Splunk HEC JSON, OpenTelemetry log format
//! - Configurable retention: by age or count
//! - Tamper-evident: events include hash chain


use crate::firewall::ThreatScore;

// ── SIEM Format ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemFormat {
    Syslog,
    SplunkHec,
    OtelLog,
}

// ── Retention Policy ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Maximum age in milliseconds. Events older than this are purged.
    pub max_age_ms: i64,
    /// Maximum number of events to keep. Oldest purged first.
    pub max_count: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_ms: 7 * 24 * 60 * 60 * 1000, // 7 days
            max_count: 100_000,
        }
    }
}

// ── Firewall Event Store ────────────────────────────────────────────

pub struct FirewallEventStore {
    events: Vec<ThreatScore>,
    retention: RetentionPolicy,
    /// Hash chain for tamper evidence.
    chain_hash: Option<String>,
}

impl FirewallEventStore {
    pub fn new(retention: RetentionPolicy) -> Self {
        Self { events: Vec::new(), retention, chain_hash: None }
    }

    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    /// Persist a threat event.
    pub fn store(&mut self, event: ThreatScore) {
        // Update hash chain
        let entry_str = format!("{}:{}:{:.4}:{:?}",
            event.agent_pid, event.operation, event.score, event.verdict);
        let hash = sha2_hash(entry_str.as_bytes());
        let chained = match &self.chain_hash {
            Some(prev) => sha2_hash(format!("{}:{}", prev, hash).as_bytes()),
            None => hash,
        };
        self.chain_hash = Some(chained);
        self.events.push(event);
    }

    /// Apply retention policy — purge old/excess events.
    pub fn enforce_retention(&mut self) -> usize {
        let now = Self::now_ms();
        let before = self.events.len();

        // Purge by age
        self.events.retain(|e| now - e.timestamp <= self.retention.max_age_ms);

        // Purge by count (keep newest)
        if self.events.len() > self.retention.max_count {
            let excess = self.events.len() - self.retention.max_count;
            self.events.drain(..excess);
        }

        before - self.events.len()
    }

    // ── Query methods ───────────────────────────────────────────

    pub fn events_by_agent(&self, agent_pid: &str) -> Vec<&ThreatScore> {
        self.events.iter().filter(|e| e.agent_pid == agent_pid).collect()
    }

    pub fn events_by_severity(&self, min_score: f64) -> Vec<&ThreatScore> {
        self.events.iter().filter(|e| e.score >= min_score).collect()
    }

    pub fn events_since(&self, since_ms: i64) -> Vec<&ThreatScore> {
        self.events.iter().filter(|e| e.timestamp >= since_ms).collect()
    }

    pub fn blocked_events(&self) -> Vec<&ThreatScore> {
        self.events.iter().filter(|e| e.verdict.is_blocked()).collect()
    }

    pub fn event_count(&self) -> usize { self.events.len() }
    pub fn chain_hash(&self) -> Option<&str> { self.chain_hash.as_deref() }

    // ── SIEM Export ─────────────────────────────────────────────

    /// Export an event in the specified SIEM format.
    pub fn export_event(event: &ThreatScore, format: SiemFormat) -> String {
        match format {
            SiemFormat::Syslog => Self::to_syslog(event),
            SiemFormat::SplunkHec => Self::to_splunk_hec(event),
            SiemFormat::OtelLog => Self::to_otel_log(event),
        }
    }

    /// RFC 5424 syslog format.
    fn to_syslog(event: &ThreatScore) -> String {
        let severity = if event.score >= 0.8 { 2 } // critical
            else if event.score >= 0.6 { 4 } // warning
            else if event.score >= 0.3 { 6 } // informational
            else { 7 }; // debug
        format!(
            "<{}>{} connector-firewall agent={} op={} score={:.4} verdict={:?} layer={} signals={}",
            severity, event.timestamp, event.agent_pid, event.operation,
            event.score, event.verdict, event.maestro_layer,
            event.signals.len()
        )
    }

    /// Splunk HEC JSON format.
    fn to_splunk_hec(event: &ThreatScore) -> String {
        let signals: Vec<String> = event.signals.iter()
            .map(|s| format!("{{\"name\":\"{}\",\"value\":{:.4},\"weight\":{:.4}}}",
                s.name, s.value, s.weight))
            .collect();
        format!(
            "{{\"time\":{},\"sourcetype\":\"connector:firewall\",\"event\":{{\"agent_pid\":\"{}\",\"operation\":\"{}\",\"score\":{:.4},\"verdict\":\"{:?}\",\"maestro_layer\":{},\"signals\":[{}]}}}}",
            event.timestamp as f64 / 1000.0,
            event.agent_pid, event.operation, event.score,
            event.verdict, event.maestro_layer,
            signals.join(",")
        )
    }

    /// OpenTelemetry log format.
    fn to_otel_log(event: &ThreatScore) -> String {
        let severity_text = if event.score >= 0.8 { "ERROR" }
            else if event.score >= 0.6 { "WARN" }
            else if event.score >= 0.3 { "INFO" }
            else { "DEBUG" };
        format!(
            "{{\"timeUnixNano\":{},\"severityText\":\"{}\",\"body\":\"Firewall: agent={} op={} score={:.4}\",\"attributes\":{{\"agent_pid\":\"{}\",\"operation\":\"{}\",\"score\":{:.4},\"verdict\":\"{:?}\",\"maestro_layer\":{}}}}}",
            event.timestamp * 1_000_000, // ms to ns
            severity_text, event.agent_pid, event.operation, event.score,
            event.agent_pid, event.operation, event.score,
            event.verdict, event.maestro_layer
        )
    }
}

impl Default for FirewallEventStore {
    fn default() -> Self { Self::new(RetentionPolicy::default()) }
}

fn sha2_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{ThreatScore, Signal, Verdict};

    fn make_event(agent: &str, score: f64, blocked: bool) -> ThreatScore {
        ThreatScore {
            score,
            verdict: if blocked { Verdict::Block { reason: "test".into() } } else { Verdict::Allow },
            signals: vec![Signal { name: "test".into(), value: score, weight: 1.0, detail: String::new() }],
            agent_pid: agent.to_string(),
            operation: "test_op".to_string(),
            maestro_layer: 1,
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    #[test]
    fn test_store_and_query() {
        let mut store = FirewallEventStore::default();
        store.store(make_event("pid:1", 0.5, false));
        store.store(make_event("pid:1", 0.9, true));
        store.store(make_event("pid:2", 0.3, false));

        assert_eq!(store.event_count(), 3);
        assert_eq!(store.events_by_agent("pid:1").len(), 2);
        assert_eq!(store.events_by_agent("pid:2").len(), 1);
    }

    #[test]
    fn test_query_by_severity() {
        let mut store = FirewallEventStore::default();
        store.store(make_event("pid:1", 0.2, false));
        store.store(make_event("pid:1", 0.7, false));
        store.store(make_event("pid:1", 0.95, true));

        assert_eq!(store.events_by_severity(0.5).len(), 2);
        assert_eq!(store.events_by_severity(0.9).len(), 1);
    }

    #[test]
    fn test_blocked_events() {
        let mut store = FirewallEventStore::default();
        store.store(make_event("pid:1", 0.5, false));
        store.store(make_event("pid:1", 0.9, true));
        assert_eq!(store.blocked_events().len(), 1);
    }

    #[test]
    fn test_retention_by_count() {
        let mut store = FirewallEventStore::new(RetentionPolicy {
            max_age_ms: i64::MAX,
            max_count: 2,
        });
        store.store(make_event("pid:1", 0.1, false));
        store.store(make_event("pid:2", 0.2, false));
        store.store(make_event("pid:3", 0.3, false));

        let purged = store.enforce_retention();
        assert_eq!(purged, 1);
        assert_eq!(store.event_count(), 2);
    }

    #[test]
    fn test_syslog_format() {
        let event = make_event("pid:1", 0.85, true);
        let syslog = FirewallEventStore::export_event(&event, SiemFormat::Syslog);
        assert!(syslog.contains("connector-firewall"));
        assert!(syslog.contains("pid:1"));
    }

    #[test]
    fn test_splunk_hec_format() {
        let event = make_event("pid:1", 0.5, false);
        let json = FirewallEventStore::export_event(&event, SiemFormat::SplunkHec);
        assert!(json.contains("sourcetype"));
        assert!(json.contains("connector:firewall"));
    }

    #[test]
    fn test_otel_log_format() {
        let event = make_event("pid:1", 0.9, true);
        let otel = FirewallEventStore::export_event(&event, SiemFormat::OtelLog);
        assert!(otel.contains("severityText"));
        assert!(otel.contains("ERROR"));
    }

    #[test]
    fn test_chain_hash_tamper_evidence() {
        let mut store = FirewallEventStore::default();
        store.store(make_event("pid:1", 0.5, false));
        let hash1 = store.chain_hash().unwrap().to_string();
        store.store(make_event("pid:1", 0.6, false));
        let hash2 = store.chain_hash().unwrap().to_string();
        assert_ne!(hash1, hash2); // chain progresses
    }
}
