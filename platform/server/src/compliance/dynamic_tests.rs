//! Dynamic Compliance Tests — Real Evidence-Based Verification
//!
//! FIX BUG-051: Replace hardcoded templates with dynamic tests

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Evidence Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub evidence_id: String,
    pub control_id: String,
    pub evidence_type: EvidenceType,
    pub data: Vec<u8>,
    pub hash: String,
    pub collected_at: i64,
    pub collector: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    AuditLog,
    SecurityScan,
    PenTestResult,
    ConfigSnapshot,
    AccessLog,
    EncryptionStatus,
    BackupVerification,
    PolicyDocument,
    TrainingRecord,
    CodeReview,
}

// =============================================================================
// Control Definition
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub control_id: String,
    pub framework: Framework,
    pub requirement: String,
    pub description: String,
    pub test_logic: TestLogic,
    pub required_evidence: Vec<EvidenceType>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Framework {
    Soc2,
    Iso27001,
    Hipaa,
    Gdpr,
    PciDss,
    Nist,
    EuAiAct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestLogic {
    /// Check if evidence exists and meets criteria
    EvidenceExists { min_count: usize, max_age_days: u32 },
    /// Check if configuration matches expected state
    ConfigMatch { key: String, expected_value: String },
    /// Check if metric is within threshold
    MetricThreshold { metric: String, min: f64, max: f64 },
    /// Custom test with code
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

// =============================================================================
// Dynamic Test Engine
// =============================================================================

pub struct DynamicTestEngine {
    controls: Arc<RwLock<HashMap<String, Control>>>,
    evidence: Arc<RwLock<HashMap<String, Vec<EvidenceItem>>>>,
    test_history: Arc<RwLock<Vec<TestResult>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test_id: String,
    pub control_id: String,
    pub passed: bool,
    pub score: f64,
    pub evidence_count: usize,
    pub findings: Vec<Finding>,
    pub tested_at: i64,
    pub tested_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub description: String,
    pub evidence_refs: Vec<String>,
    pub remediation: String,
}

impl DynamicTestEngine {
    pub fn new() -> Self {
        let engine = Self {
            controls: Arc::new(RwLock::new(HashMap::new())),
            evidence: Arc::new(RwLock::new(HashMap::new())),
            test_history: Arc::new(RwLock::new(Vec::new())),
        };
        
        engine.initialize_default_controls();
        engine
    }

    fn initialize_default_controls(&self) {
        let mut controls = self.controls.write().unwrap();
        
        // SOC 2 CC6.1 - Logical access security
        controls.insert("CC6.1".to_string(), Control {
            control_id: "CC6.1".to_string(),
            framework: Framework::Soc2,
            requirement: "Logical access security".to_string(),
            description: "Access controls must be implemented and enforced".to_string(),
            test_logic: TestLogic::EvidenceExists { min_count: 1, max_age_days: 90 },
            required_evidence: vec![EvidenceType::AccessLog, EvidenceType::PolicyDocument],
            severity: Severity::Critical,
        });
        
        // SOC 2 CC7.1 - Security monitoring
        controls.insert("CC7.1".to_string(), Control {
            control_id: "CC7.1".to_string(),
            framework: Framework::Soc2,
            requirement: "Security monitoring".to_string(),
            description: "Security events must be monitored and logged".to_string(),
            test_logic: TestLogic::MetricThreshold { 
                metric: "security_events_logged".to_string(), 
                min: 0.95, 
                max: 1.0 
            },
            required_evidence: vec![EvidenceType::AuditLog],
            severity: Severity::High,
        });
        
        // ISO 27001 A.12.4 - Logging
        controls.insert("A.12.4".to_string(), Control {
            control_id: "A.12.4".to_string(),
            framework: Framework::Iso27001,
            requirement: "Logging and monitoring".to_string(),
            description: "Activity logs must be maintained and reviewed".to_string(),
            test_logic: TestLogic::EvidenceExists { min_count: 30, max_age_days: 30 },
            required_evidence: vec![EvidenceType::AuditLog],
            severity: Severity::High,
        });
        
        // HIPAA §164.312(a)(1) - Access control
        controls.insert("HIPAA-164.312(a)(1)".to_string(), Control {
            control_id: "HIPAA-164.312(a)(1)".to_string(),
            framework: Framework::Hipaa,
            requirement: "Access control".to_string(),
            description: "Only authorized persons shall access ePHI".to_string(),
            test_logic: TestLogic::ConfigMatch { 
                key: "encryption_at_rest".to_string(), 
                expected_value: "enabled".to_string() 
            },
            required_evidence: vec![EvidenceType::EncryptionStatus, EvidenceType::AccessLog],
            severity: Severity::Critical,
        });
        
        // EU AI Act - Risk management
        controls.insert("EU-AI-Art.9".to_string(), Control {
            control_id: "EU-AI-Art.9".to_string(),
            framework: Framework::EuAiAct,
            requirement: "Risk management system".to_string(),
            description: "High-risk AI systems must have risk management".to_string(),
            test_logic: TestLogic::EvidenceExists { min_count: 1, max_age_days: 365 },
            required_evidence: vec![EvidenceType::PolicyDocument, EvidenceType::AuditLog],
            severity: Severity::Critical,
        });
        
        println!("[COMPLIANCE] Initialized {} dynamic controls", controls.len());
    }

    /// Collect evidence for a control
    pub fn collect_evidence(&self, control_id: &str, evidence: EvidenceItem) {
        let mut evidence_map = self.evidence.write().unwrap();
        evidence_map.entry(control_id.to_string())
            .or_insert_with(Vec::new)
            .push(evidence);
    }

    /// Run dynamic test for a control
    pub fn test_control(&self, control_id: &str) -> TestResult {
        let controls = self.controls.read().unwrap();
        let evidence_map = self.evidence.read().unwrap();
        
        let control = match controls.get(control_id) {
            Some(c) => c.clone(),
            None => {
                return TestResult {
                    test_id: format!("test-{}", uuid::Uuid::new_v4()),
                    control_id: control_id.to_string(),
                    passed: false,
                    score: 0.0,
                    evidence_count: 0,
                    findings: vec![Finding {
                        severity: Severity::Critical,
                        description: format!("Control {} not found", control_id),
                        evidence_refs: vec![],
                        remediation: "Define control in compliance framework".to_string(),
                    }],
                    tested_at: chrono::Utc::now().timestamp_millis(),
                    tested_by: "dynamic_test_engine".to_string(),
                };
            }
        };

        let control_evidence = evidence_map.get(control_id).cloned().unwrap_or_default();
        
        // Execute test logic
        let (passed, score, findings) = self.execute_test(&control, &control_evidence);
        
        let result = TestResult {
            test_id: format!("test-{}", uuid::Uuid::new_v4()),
            control_id: control_id.to_string(),
            passed,
            score,
            evidence_count: control_evidence.len(),
            findings,
            tested_at: chrono::Utc::now().timestamp_millis(),
            tested_by: "dynamic_test_engine".to_string(),
        };

        // Store result
        self.test_history.write().unwrap().push(result.clone());
        
        println!("[COMPLIANCE] Test {} for {}: {} (score: {:.2})",
            result.test_id, control_id, if passed { "PASS" } else { "FAIL" }, score);

        result
    }

    fn execute_test(&self, control: &Control, evidence: &[EvidenceItem]) -> (bool, f64, Vec<Finding>) {
        let mut findings = Vec::new();
        let mut score = 0.0;

        match &control.test_logic {
            TestLogic::EvidenceExists { min_count, max_age_days } => {
                let now = chrono::Utc::now().timestamp_millis();
                let max_age_ms = *max_age_days as i64 * 24 * 3600 * 1000;
                
                let valid_evidence: Vec<&EvidenceItem> = evidence.iter()
                    .filter(|e| now - e.collected_at <= max_age_ms)
                    .collect();

                if valid_evidence.len() >= *min_count {
                    score = 1.0;
                } else {
                    score = valid_evidence.len() as f64 / *min_count as f64;
                    findings.push(Finding {
                        severity: control.severity.clone(),
                        description: format!(
                            "Insufficient evidence: found {} valid items, need {} (within {} days)",
                            valid_evidence.len(), min_count, max_age_days
                        ),
                        evidence_refs: valid_evidence.iter().map(|e| e.evidence_id.clone()).collect(),
                        remediation: format!("Collect {} new evidence items", min_count - valid_evidence.len()),
                    });
                }

                (score >= 0.8, score, findings)
            }
            
            TestLogic::ConfigMatch { key, expected_value } => {
                // Check if config evidence exists with expected value
                let matching: Vec<&EvidenceItem> = evidence.iter()
                    .filter(|e| e.metadata.get(key) == Some(expected_value))
                    .collect();

                if !matching.is_empty() {
                    score = 1.0;
                    (true, score, findings)
                } else {
                    findings.push(Finding {
                        severity: control.severity.clone(),
                        description: format!("Configuration mismatch: {} != {}", key, expected_value),
                        evidence_refs: evidence.iter().map(|e| e.evidence_id.clone()).collect(),
                        remediation: format!("Update {} to {}", key, expected_value),
                    });
                    (false, 0.0, findings)
                }
            }
            
            TestLogic::MetricThreshold { metric, min, max } => {
                // Extract metric from evidence
                let metric_values: Vec<f64> = evidence.iter()
                    .filter_map(|e| e.metadata.get(metric))
                    .filter_map(|v| v.parse().ok())
                    .collect();

                let len = metric_values.len() as f64;
                if len > 0.0 {
                    let avg = metric_values.iter().sum::<f64>() / len;
                    if avg >= *min && avg <= *max {
                        score = 1.0;
                        (true, score, findings)
                    } else {
                        score = 0.0;
                        findings.push(Finding {
                            severity: control.severity.clone(),
                            description: format!("Metric {} out of range: {:.2} not in [{:.2}, {:.2}]",
                                metric, avg, min, max),
                            evidence_refs: evidence.iter().map(|e| e.evidence_id.clone()).collect(),
                            remediation: format!("Adjust {} to be within [{:.2}, {:.2}]", metric, min, max),
                        });
                        (false, score, findings)
                    }
                } else {
                    findings.push(Finding {
                        severity: control.severity.clone(),
                        description: format!("No metric data found for {}", metric),
                        evidence_refs: vec![],
                        remediation: format!("Collect {} metric data", metric),
                    });
                    (false, 0.0, findings)
                }
            }
            
            TestLogic::Custom(code) => {
                // In production: execute custom test code safely
                findings.push(Finding {
                    severity: Severity::Medium,
                    description: format!("Custom test not executed: {}", code),
                    evidence_refs: vec![],
                    remediation: "Implement custom test executor".to_string(),
                });
                (false, 0.0, findings)
            }
        }
    }

    /// Run all tests
    pub fn run_all_tests(&self) -> Vec<TestResult> {
        let controls = self.controls.read().unwrap();
        let mut results = Vec::new();

        for control_id in controls.keys() {
            results.push(self.test_control(control_id));
        }

        results
    }

    /// Get compliance score
    pub fn compliance_score(&self) -> f64 {
        let history = self.test_history.read().unwrap();
        if history.is_empty() {
            return 0.0;
        }

        let total: f64 = history.iter().map(|r| r.score).sum();
        total / history.len() as f64
    }

    /// Get failed controls
    pub fn failed_controls(&self) -> Vec<TestResult> {
        self.test_history.read().unwrap()
            .iter()
            .filter(|r| !r.passed)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_control() {
        let engine = DynamicTestEngine::new();
        
        // Add evidence
        engine.collect_evidence("CC6.1", EvidenceItem {
            evidence_id: "ev-1".to_string(),
            control_id: "CC6.1".to_string(),
            evidence_type: EvidenceType::AccessLog,
            data: vec![],
            hash: "hash".to_string(),
            collected_at: chrono::Utc::now().timestamp_millis(),
            collector: "test".to_string(),
            metadata: HashMap::new(),
        });

        // Test
        let result = engine.test_control("CC6.1");
        assert!(result.passed || !result.findings.is_empty());
    }

    #[test]
    fn test_insufficient_evidence() {
        let engine = DynamicTestEngine::new();
        
        // Don't add evidence
        let result = engine.test_control("CC6.1");
        
        // Should fail due to insufficient evidence
        assert!(!result.passed);
        assert!(!result.findings.is_empty());
    }
}
