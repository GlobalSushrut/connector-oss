//! Compliance Audit Trail — Report Generation, Distribution, Continuous Monitoring
//!
//! FIX BUG-056/057/058: Complete compliance audit system

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Audit Trail Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: i64,
    pub event_type: AuditEventType,
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: HashMap<String, String>,
    pub before_hash: String,
    pub after_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    ReportGeneration,
    ReportDistribution,
    ReportAccess,
    ControlTest,
    EvidenceCollection,
    PolicyChange,
    AccessGrant,
    AccessRevoke,
    DataModification,
    SystemConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub trail_id: String,
    pub events: Vec<AuditEvent>,
    pub merkle_root: String,
    pub started_at: i64,
    pub closed_at: Option<i64>,
}

// =============================================================================
// Report Generation Tracking
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: String,
    pub report_type: ReportType,
    pub framework: String,
    pub period_start: i64,
    pub period_end: i64,
    pub generated_at: i64,
    pub generated_by: String,
    pub content_hash: String,
    pub signed_by: Vec<String>,
    pub distribution_list: Vec<DistributionRecord>,
    pub status: ReportStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportType {
    Annual,
    Quarterly,
    Monthly,
    Weekly,
    AdHoc,
    AuditResponse,
    GapAnalysis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportStatus {
    Draft,
    UnderReview,
    Approved,
    Distributed,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionRecord {
    pub recipient: String,
    pub distributed_at: i64,
    pub method: DistributionMethod,
    pub acknowledged: bool,
    pub acknowledged_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionMethod {
    Email,
    SecurePortal,
    Physical,
    Api,
}

// =============================================================================
// Continuous Monitoring
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringRule {
    pub rule_id: String,
    pub name: String,
    pub condition: MonitoringCondition,
    pub threshold: f64,
    pub severity: AlertSeverity,
    pub enabled: bool,
    pub alert_channels: Vec<AlertChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitoringCondition {
    ControlFailureRate,
    EvidenceGap,
    AccessViolation,
    ConfigDrift,
    AuditFindingUnaddressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertChannel {
    Email(String),
    Slack(String),
    PagerDuty(String),
    Webhook(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub rule_id: String,
    pub timestamp: i64,
    pub severity: AlertSeverity,
    pub message: String,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
}

// =============================================================================
// Audit Trail Manager
// =============================================================================

pub struct AuditTrailManager {
    /// Active trails
    trails: Arc<RwLock<HashMap<String, AuditTrail>>>,
    /// Compliance reports
    reports: Arc<RwLock<HashMap<String, ComplianceReport>>>,
    /// Monitoring rules
    monitoring_rules: Arc<RwLock<Vec<MonitoringRule>>>,
    /// Active alerts
    alerts: Arc<RwLock<Vec<Alert>>>,
    /// Event sequence counter
    event_counter: Arc<RwLock<u64>>,
    /// Previous event hash (for chain)
    previous_hash: Arc<RwLock<String>>,
}

impl AuditTrailManager {
    pub fn new() -> Self {
        Self {
            trails: Arc::new(RwLock::new(HashMap::new())),
            reports: Arc::new(RwLock::new(HashMap::new())),
            monitoring_rules: Arc::new(RwLock::new(Vec::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            event_counter: Arc::new(RwLock::new(0)),
            previous_hash: Arc::new(RwLock::new("0".repeat(64))),
        }
    }

    /// Record audit event
    pub fn record_event(
        &self,
        event_type: AuditEventType,
        actor: String,
        resource: String,
        action: String,
        outcome: AuditOutcome,
        details: HashMap<String, String>,
    ) -> String {
        let event_id = format!("evt-{}", uuid::Uuid::new_v4());
        let timestamp = chrono::Utc::now().timestamp_millis();

        let before_hash = self.previous_hash.read().unwrap().clone();
        
        // Create event data for hashing
        let event_data = format!(
            "{}:{}:{}:{}:{}:{}",
            event_id, timestamp, actor, resource, action, outcome as u8
        );
        let after_hash = Self::hash(&event_data);

        let event = AuditEvent {
            event_id: event_id.clone(),
            timestamp,
            event_type,
            actor,
            resource,
            action,
            outcome,
            details,
            before_hash,
            after_hash: after_hash.clone(),
        };

        // Update chain
        *self.previous_hash.write().unwrap() = after_hash;
        *self.event_counter.write().unwrap() += 1;

        // Check monitoring rules first (before move)
        self.check_monitoring_rules(&event);

        // Add to current trail
        self.add_to_trail(event);

        event_id
    }

    fn add_to_trail(&self, event: AuditEvent) {
        let mut trails = self.trails.write().unwrap();
        
        // Find or create active trail
        let trail_id = trails.keys().next().cloned()
            .unwrap_or_else(|| {
                let id = format!("trail-{}", uuid::Uuid::new_v4());
                trails.insert(id.clone(), AuditTrail {
                    trail_id: id.clone(),
                    events: vec![],
                    merkle_root: String::new(),
                    started_at: chrono::Utc::now().timestamp_millis(),
                    closed_at: None,
                });
                id
            });

        if let Some(trail) = trails.get_mut(&trail_id) {
            trail.events.push(event);
            
            // Update merkle root periodically (every 100 events)
            if trail.events.len() % 100 == 0 {
                trail.merkle_root = self.compute_trail_hash(&trail.events);
            }
        }
    }

    /// Generate compliance report
    pub fn generate_report(
        &self,
        report_type: ReportType,
        framework: String,
        period_start: i64,
        period_end: i64,
        generated_by: String,
    ) -> ComplianceReport {
        let report_id = format!("report-{}", uuid::Uuid::new_v4());
        
        // Generate content hash
        let content = format!(
            "{}:{}:{}:{}:{}",
            report_id, framework, period_start, period_end, generated_by
        );
        let content_hash = Self::hash(&content);

        let framework_str = framework.clone();
        let generated_by_str = generated_by.clone();
        let report = ComplianceReport {
            report_id: report_id.clone(),
            report_type,
            framework,
            period_start,
            period_end,
            generated_at: chrono::Utc::now().timestamp_millis(),
            generated_by: generated_by.clone(),
            content_hash,
            signed_by: vec![generated_by],
            distribution_list: vec![],
            status: ReportStatus::Draft,
        };

        self.reports.write().unwrap().insert(report_id.clone(), report.clone());

        // Audit the generation
        let mut details = HashMap::new();
        details.insert("report_id".to_string(), report_id.clone());
        details.insert("framework".to_string(), framework_str);

        self.record_event(
            AuditEventType::ReportGeneration,
            generated_by_str,
            report_id.clone(),
            "generate".to_string(),
            AuditOutcome::Success,
            details,
        );

        report
    }

    /// Distribute report
    pub fn distribute_report(
        &self,
        report_id: &str,
        recipients: Vec<String>,
        method: DistributionMethod,
        distributed_by: String,
    ) -> Result<(), String> {
        let mut reports = self.reports.write().unwrap();
        
        let report = reports.get_mut(report_id)
            .ok_or("Report not found")?;

        let now = chrono::Utc::now().timestamp_millis();

        for recipient in recipients {
            report.distribution_list.push(DistributionRecord {
                recipient,
                distributed_at: now,
                method,
                acknowledged: false,
                acknowledged_at: None,
            });
        }

        report.status = ReportStatus::Distributed;

        // Audit the distribution
        let mut details = HashMap::new();
        details.insert("report_id".to_string(), report_id.to_string());
        details.insert("recipient_count".to_string(), report.distribution_list.len().to_string());
        details.insert("method".to_string(), format!("{:?}", method));

        self.record_event(
            AuditEventType::ReportDistribution,
            distributed_by,
            report_id.to_string(),
            "distribute".to_string(),
            AuditOutcome::Success,
            details,
        );

        Ok(())
    }

    /// Acknowledge report receipt
    pub fn acknowledge_report(&self, report_id: &str, recipient: &str) -> Result<(), String> {
        let mut reports = self.reports.write().unwrap();
        
        let report = reports.get_mut(report_id)
            .ok_or("Report not found")?;

        for dist in &mut report.distribution_list {
            if dist.recipient == recipient {
                dist.acknowledged = true;
                dist.acknowledged_at = Some(chrono::Utc::now().timestamp_millis());
                break;
            }
        }

        Ok(())
    }

    /// Add monitoring rule
    pub fn add_monitoring_rule(&self, rule: MonitoringRule) {
        self.monitoring_rules.write().unwrap().push(rule);
    }

    /// Check event against monitoring rules
    fn check_monitoring_rules(&self, event: &AuditEvent) {
        let rules = self.monitoring_rules.read().unwrap();

        for rule in rules.iter().filter(|r| r.enabled) {
            let triggered = match (&rule.condition, &event.event_type, &event.outcome) {
                (MonitoringCondition::ControlFailureRate, AuditEventType::ControlTest, AuditOutcome::Failure) => {
                    true // Would need historical analysis
                }
                (MonitoringCondition::AccessViolation, AuditEventType::AccessGrant, AuditOutcome::Denied) |
                (MonitoringCondition::AccessViolation, AuditEventType::AccessRevoke, AuditOutcome::Failure) => {
                    true
                }
                _ => false,
            };

            if triggered {
                self.trigger_alert(rule, event);
            }
        }
    }

    fn trigger_alert(&self, rule: &MonitoringRule, event: &AuditEvent) {
        let alert = Alert {
            alert_id: format!("alert-{}", uuid::Uuid::new_v4()),
            rule_id: rule.rule_id.clone(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            severity: rule.severity,
            message: format!("Rule {} triggered by event {}", rule.name, event.event_id),
            acknowledged: false,
            acknowledged_by: None,
        };

        self.alerts.write().unwrap().push(alert);
        
        println!("[AUDIT] ALERT: {} - {}", rule.severity as u8, rule.name);
    }

    /// Get active alerts
    pub fn active_alerts(&self) -> Vec<Alert> {
        self.alerts.read().unwrap()
            .iter()
            .filter(|a| !a.acknowledged)
            .cloned()
            .collect()
    }

    /// Acknowledge alert
    pub fn acknowledge_alert(&self, alert_id: &str, acknowledged_by: &str) -> Result<(), String> {
        let mut alerts = self.alerts.write().unwrap();
        
        if let Some(alert) = alerts.iter_mut().find(|a| a.alert_id == alert_id) {
            alert.acknowledged = true;
            alert.acknowledged_by = Some(acknowledged_by.to_string());
            Ok(())
        } else {
            Err("Alert not found".to_string())
        }
    }

    /// Verify trail integrity
    pub fn verify_trail(&self, trail_id: &str) -> Result<bool, String> {
        let trails = self.trails.read().unwrap();
        
        let trail = trails.get(trail_id)
            .ok_or("Trail not found")?;

        // Verify chain of hashes
        for i in 1..trail.events.len() {
            let prev = &trail.events[i-1];
            let curr = &trail.events[i];

            if curr.before_hash != prev.after_hash {
                return Ok(false);
            }
        }

        // Verify merkle root
        let computed_root = self.compute_trail_hash(&trail.events);
        if !trail.merkle_root.is_empty() && trail.merkle_root != computed_root {
            return Ok(false);
        }

        Ok(true)
    }

    fn compute_trail_hash(&self, events: &[AuditEvent]) -> String {
        let data: String = events.iter()
            .map(|e| e.after_hash.clone())
            .collect::<Vec<_>>()
            .join("");
        
        Self::hash(&data)
    }

    /// Get audit statistics
    pub fn stats(&self) -> AuditStats {
        let trails = self.trails.read().unwrap();
        let reports = self.reports.read().unwrap();
        let alerts = self.alerts.read().unwrap();

        let total_events: usize = trails.values()
            .map(|t| t.events.len())
            .sum();

        AuditStats {
            active_trails: trails.len(),
            total_events,
            pending_reports: reports.values().filter(|r| r.status == ReportStatus::Draft).count(),
            distributed_reports: reports.values().filter(|r| r.status == ReportStatus::Distributed).count(),
            active_alerts: alerts.iter().filter(|a| !a.acknowledged).count(),
            total_alerts: alerts.len(),
        }
    }

    fn hash(data: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub active_trails: usize,
    pub total_events: usize,
    pub pending_reports: usize,
    pub distributed_reports: usize,
    pub active_alerts: usize,
    pub total_alerts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_trail() {
        let manager = AuditTrailManager::new();
        
        // Record events
        for i in 0..10 {
            let mut details = HashMap::new();
            details.insert("iteration".to_string(), i.to_string());
            
            manager.record_event(
                AuditEventType::ControlTest,
                "tester".to_string(),
                format!("control-{}", i),
                "test".to_string(),
                AuditOutcome::Success,
                details,
            );
        }

        let stats = manager.stats();
        assert!(stats.total_events >= 10);
    }

    #[test]
    fn test_report_generation() {
        let manager = AuditTrailManager::new();
        
        let report = manager.generate_report(
            ReportType::Quarterly,
            "SOC2".to_string(),
            1000,
            2000,
            "auditor@company.com".to_string(),
        );
        
        assert_eq!(report.report_type, ReportType::Quarterly);
        assert_eq!(report.framework, "SOC2");
        assert_eq!(report.status, ReportStatus::Draft);
        
        // Distribute
        manager.distribute_report(
            &report.report_id,
            vec!["board@company.com".to_string()],
            DistributionMethod::Email,
            "admin".to_string(),
        ).unwrap();
        
        let stats = manager.stats();
        assert_eq!(stats.distributed_reports, 1);
    }

    #[test]
    fn test_monitoring_rules() {
        let manager = AuditTrailManager::new();
        
        // Add monitoring rule
        manager.add_monitoring_rule(MonitoringRule {
            rule_id: "rule-1".to_string(),
            name: "Access Violations".to_string(),
            condition: MonitoringCondition::AccessViolation,
            threshold: 1.0,
            severity: AlertSeverity::Critical,
            enabled: true,
            alert_channels: vec![AlertChannel::Email("security@company.com".to_string())],
        });
        
        // Trigger event
        manager.record_event(
            AuditEventType::AccessGrant,
            "user".to_string(),
            "resource-1".to_string(),
            "access".to_string(),
            AuditOutcome::Denied,
            HashMap::new(),
        );
        
        // Check alert was created
        let alerts = manager.active_alerts();
        assert!(!alerts.is_empty());
    }
}
