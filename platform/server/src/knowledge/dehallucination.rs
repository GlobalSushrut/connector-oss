//! De-hallucination Chain — Ground Truth Verification
//!
//! FIX BUG-046: Detect and retract hallucinations

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Hallucination Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HallucinationType {
    /// Confabulated (made up) facts
    Confabulation,
    /// Unsupported inference
    UnsupportedInference,
    /// Contradiction with known truth
    Contradiction,
    /// Overgeneralization
    Overgeneralization,
    /// Source misattribution
    SourceMisattribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HallucinationReport {
    pub report_id: String,
    pub fact_id: String,
    pub hallucination_type: HallucinationType,
    pub severity: f64,
    pub description: String,
    pub evidence: Vec<VerificationEvidence>,
    pub detected_at: i64,
    pub status: ReportStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportStatus {
    PendingReview,
    Confirmed,
    FalsePositive,
    Retracted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub evidence_type: EvidenceType,
    pub source: String,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    GroundTruth,
    SourceDocument,
    ExpertReview,
    StatisticalAnalysis,
    LogicalInference,
}

// =============================================================================
// Ground Truth Database
// =============================================================================

pub struct GroundTruthDB {
    /// Verified facts
    facts: Arc<RwLock<HashMap<String, GroundTruthFact>>>,
    /// Source reliability scores
    source_scores: Arc<RwLock<HashMap<String, f64>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthFact {
    pub fact_id: String,
    pub statement: String,
    pub confidence: f64,
    pub sources: Vec<String>,
    pub verified_by: Vec<String>,
    pub verified_at: i64,
    pub version: u32,
}

impl GroundTruthDB {
    pub fn new() -> Self {
        Self {
            facts: Arc::new(RwLock::new(HashMap::new())),
            source_scores: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add verified fact
    pub fn add_fact(&self, fact: GroundTruthFact) {
        self.facts.write().unwrap().insert(fact.fact_id.clone(), fact);
    }

    /// Query ground truth
    pub fn query(&self, query: &str) -> Option<GroundTruthFact> {
        // In production: semantic search over facts
        // For now: simple exact match
        self.facts.read().unwrap().values()
            .find(|f| f.statement.contains(query))
            .cloned()
    }

    /// Check if fact contradicts ground truth
    pub fn check_contradiction(&self, statement: &str) -> Option<GroundTruthFact> {
        // In production: semantic contradiction detection
        self.facts.read().unwrap().values()
            .find(|f| {
                // Simple contradiction check
                let f_lower = f.statement.to_lowercase();
                let s_lower = statement.to_lowercase();
                
                (f_lower.contains("is true") && s_lower.contains("is false")) ||
                (f_lower.contains("is false") && s_lower.contains("is true"))
            })
            .cloned()
    }

    /// Update source reliability
    pub fn update_source_score(&self, source: &str, score_delta: f64) {
        let mut scores = self.source_scores.write().unwrap();
        let current = scores.get(source).copied().unwrap_or(0.5);
        scores.insert(source.to_string(), (current + score_delta).clamp(0.0, 1.0));
    }

    pub fn get_source_score(&self, source: &str) -> f64 {
        self.source_scores.read().unwrap()
            .get(source)
            .copied()
            .unwrap_or(0.5)
    }
}

// =============================================================================
// Hallucination Detector
// =============================================================================

pub struct HallucinationDetector {
    ground_truth: Arc<GroundTruthDB>,
    suspicious_patterns: Vec<String>,
    min_source_confidence: f64,
}

impl HallucinationDetector {
    pub fn new(ground_truth: Arc<GroundTruthDB>) -> Self {
        Self {
            ground_truth,
            suspicious_patterns: vec![
                "I think".to_string(),
                "probably".to_string(),
                "maybe".to_string(),
                "I'm not sure but".to_string(),
                "it could be".to_string(),
            ],
            min_source_confidence: 0.7,
        }
    }

    /// Analyze statement for hallucinations
    pub fn analyze(&self, fact_id: &str, statement: &str, sources: &[String]) -> Option<HallucinationReport> {
        let mut evidences = Vec::new();
        let mut severity = 0.0;
        let mut hall_type = None;

        // Check 1: Contradiction with ground truth
        if let Some(contradiction) = self.ground_truth.check_contradiction(statement) {
            hall_type = Some(HallucinationType::Contradiction);
            severity = 0.9;
            evidences.push(VerificationEvidence {
                evidence_type: EvidenceType::GroundTruth,
                source: contradiction.fact_id.clone(),
                description: format!("Contradicts verified fact: {}", contradiction.statement),
                confidence: contradiction.confidence,
            });
        }

        // Check 2: Low source reliability
        let avg_source_score: f64 = sources.iter()
            .map(|s| self.ground_truth.get_source_score(s))
            .sum::<f64>() / sources.len().max(1) as f64;

        if avg_source_score < self.min_source_confidence {
            if severity < 0.7 {
                hall_type = Some(HallucinationType::SourceMisattribution);
                severity = 0.7;
            }
            evidences.push(VerificationEvidence {
                evidence_type: EvidenceType::StatisticalAnalysis,
                source: "source-reliability".to_string(),
                description: format!("Low source reliability: {:.2}", avg_source_score),
                confidence: 1.0 - avg_source_score,
            });
        }

        // Check 3: Suspicious patterns (hedge words)
        let pattern_matches: Vec<&str> = self.suspicious_patterns.iter()
            .filter(|p| statement.to_lowercase().contains(&p.to_lowercase()))
            .map(|p| p.as_str())
            .collect();

        if !pattern_matches.is_empty() {
            if severity < 0.5 {
                hall_type = Some(HallucinationType::Confabulation);
                severity = 0.5;
            }
            evidences.push(VerificationEvidence {
                evidence_type: EvidenceType::StatisticalAnalysis,
                source: "linguistic-analysis".to_string(),
                description: format!("Suspicious patterns: {:?}", pattern_matches),
                confidence: 0.6,
            });
        }

        // Check 4: Missing sources
        if sources.is_empty() {
            if severity < 0.8 {
                hall_type = Some(HallucinationType::UnsupportedInference);
                severity = 0.8;
            }
            evidences.push(VerificationEvidence {
                evidence_type: EvidenceType::LogicalInference,
                source: "source-verification".to_string(),
                description: "No sources provided".to_string(),
                confidence: 0.9,
            });
        }

        // Return report if hallucination detected
        hall_type.map(|ht| HallucinationReport {
            report_id: format!("hr-{}", uuid::Uuid::new_v4()),
            fact_id: fact_id.to_string(),
            hallucination_type: ht,
            severity,
            description: format!("Detected {:?} in fact {}", ht, fact_id),
            evidence: evidences,
            detected_at: chrono::Utc::now().timestamp_millis(),
            status: ReportStatus::PendingReview,
        })
    }

    /// Batch analyze multiple facts
    pub fn analyze_batch(&self, facts: &[(String, String, Vec<String>)]) -> Vec<HallucinationReport> {
        facts.iter()
            .filter_map(|(id, stmt, sources)| self.analyze(id, stmt, sources))
            .collect()
    }
}

// =============================================================================
// De-hallucination Chain
// =============================================================================

pub struct DehallucinationChain {
    ground_truth: Arc<GroundTruthDB>,
    detector: HallucinationDetector,
    reports: Arc<RwLock<VecDeque<HallucinationReport>>>,
    retracted_facts: Arc<RwLock<HashSet<String>>>,
}

impl DehallucinationChain {
    pub fn new() -> Self {
        let ground_truth = Arc::new(GroundTruthDB::new());
        let detector = HallucinationDetector::new(ground_truth.clone());
        
        Self {
            ground_truth,
            detector,
            reports: Arc::new(RwLock::new(VecDeque::new())),
            retracted_facts: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Submit fact for verification
    pub fn submit_fact(&self, fact_id: String, statement: String, sources: Vec<String>) -> Option<String> {
        if let Some(report) = self.detector.analyze(&fact_id, &statement, &sources) {
            let report_id = report.report_id.clone();
            self.reports.write().unwrap().push_back(report);
            
            // Auto-retract high-severity
            if self.should_auto_retract(&report_id) {
                self.retract_fact(&fact_id, &report_id);
            }
            
            Some(report_id)
        } else {
            None
        }
    }

    /// Check if should auto-retract
    fn should_auto_retract(&self, report_id: &str) -> bool {
        let reports = self.reports.read().unwrap();
        reports.iter()
            .find(|r| r.report_id == report_id)
            .map(|r| r.severity > 0.85 && r.status == ReportStatus::PendingReview)
            .unwrap_or(false)
    }

    /// Retract a fact
    pub fn retract_fact(&self, fact_id: &str, report_id: &str) -> bool {
        // Mark as retracted
        self.retracted_facts.write().unwrap().insert(fact_id.to_string());
        
        // Update report status
        let mut reports = self.reports.write().unwrap();
        if let Some(report) = reports.iter_mut().find(|r| r.report_id == report_id) {
            report.status = ReportStatus::Retracted;
        }

        // Update source scores (penalize)
        if let Some(report) = reports.iter().find(|r| r.report_id == report_id) {
            for evidence in &report.evidence {
                if evidence.evidence_type == EvidenceType::SourceDocument {
                    self.ground_truth.update_source_score(&evidence.source, -0.1);
                }
            }
        }

        println!("[DEHALLUCINATION] Retracted fact {} (report {})", fact_id, report_id);
        true
    }

    /// Confirm fact as not hallucination
    pub fn confirm_fact(&self, fact_id: &str, report_id: &str, verified_by: &str) -> bool {
        let mut reports = self.reports.write().unwrap();
        
        if let Some(report) = reports.iter_mut().find(|r| r.report_id == report_id) {
            report.status = ReportStatus::FalsePositive;
            report.evidence.push(VerificationEvidence {
                evidence_type: EvidenceType::ExpertReview,
                source: verified_by.to_string(),
                description: "Manual verification: not hallucination".to_string(),
                confidence: 0.95,
            });

            // Boost source scores
            for evidence in &report.evidence {
                if evidence.evidence_type == EvidenceType::SourceDocument {
                    self.ground_truth.update_source_score(&evidence.source, 0.05);
                }
            }

            println!("[DEHALLUCINATION] Confirmed fact {} as valid (verified by {})", fact_id, verified_by);
            true
        } else {
            false
        }
    }

    /// Add ground truth fact
    pub fn add_ground_truth(&self, statement: &str, confidence: f64, sources: Vec<String>) -> String {
        let fact_id = format!("gt-{}", uuid::Uuid::new_v4());
        
        let fact = GroundTruthFact {
            fact_id: fact_id.clone(),
            statement: statement.to_string(),
            confidence,
            sources: sources.clone(),
            verified_by: vec!["system".to_string()],
            verified_at: chrono::Utc::now().timestamp_millis(),
            version: 1,
        };

        self.ground_truth.add_fact(fact);

        // Boost source scores
        for source in &sources {
            self.ground_truth.update_source_score(source, 0.1);
        }

        fact_id
    }

    /// Get pending reports
    pub fn pending_reports(&self) -> Vec<HallucinationReport> {
        self.reports.read().unwrap()
            .iter()
            .filter(|r| r.status == ReportStatus::PendingReview)
            .cloned()
            .collect()
    }

    /// Get retraction status
    pub fn is_retracted(&self, fact_id: &str) -> bool {
        self.retracted_facts.read().unwrap().contains(fact_id)
    }

    /// Get statistics
    pub fn stats(&self) -> DehallucinationStats {
        let reports = self.reports.read().unwrap();
        let retracted = self.retracted_facts.read().unwrap();

        DehallucinationStats {
            total_reports: reports.len(),
            pending_review: reports.iter().filter(|r| r.status == ReportStatus::PendingReview).count(),
            confirmed_hallucinations: reports.iter().filter(|r| r.status == ReportStatus::Confirmed).count(),
            false_positives: reports.iter().filter(|r| r.status == ReportStatus::FalsePositive).count(),
            retracted_facts: retracted.len(),
            ground_truth_facts: self.ground_truth.facts.read().unwrap().len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehallucinationStats {
    pub total_reports: usize,
    pub pending_review: usize,
    pub confirmed_hallucinations: usize,
    pub false_positives: usize,
    pub retracted_facts: usize,
    pub ground_truth_facts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hallucination_detection() {
        let ground_truth = Arc::new(GroundTruthDB::new());
        ground_truth.add_fact(GroundTruthFact {
            fact_id: "gt-1".to_string(),
            statement: "The sky is blue".to_string(),
            confidence: 0.99,
            sources: vec!["science".to_string()],
            verified_by: vec!["expert".to_string()],
            verified_at: 1000,
            version: 1,
        });

        let detector = HallucinationDetector::new(ground_truth);

        // Should detect contradiction
        let report = detector.analyze("f-1", "The sky is green", &vec![]);
        assert!(report.is_some());
        assert_eq!(report.unwrap().hallucination_type, HallucinationType::Contradiction);

        // Should not detect (no contradiction)
        let report = detector.analyze("f-2", "The grass is green", &vec!["botany".to_string()]);
        assert!(report.is_none());
    }

    #[test]
    fn test_dehallucination_chain() {
        let chain = DehallucinationChain::new();

        // Add ground truth
        chain.add_ground_truth("Water freezes at 0°C", 0.99, vec!["physics".to_string()]);

        // Submit false fact
        let report_id = chain.submit_fact(
            "f-1".to_string(),
            "Water freezes at 100°C".to_string(),
            vec!["unreliable".to_string()],
        );

        assert!(report_id.is_some());

        // Check if auto-retracted (high severity)
        assert!(chain.is_retracted("f-1"));

        let stats = chain.stats();
        assert!(stats.total_reports > 0);
    }
}
