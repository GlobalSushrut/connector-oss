//! Advanced Judgment Engine — multi-signal trust scoring with 8 dimensions.

use vac_core::kernel::MemoryKernel;
use vac_core::types::*;
use crate::claims::ClaimSet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgmentDimensions {
    pub cid_integrity: f64,
    pub audit_coverage: f64,
    pub access_control: f64,
    pub evidence_quality: f64,
    pub claim_coverage: f64,
    pub temporal_freshness: f64,
    pub contradiction_score: f64,
    pub source_credibility: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgmentWeighted {
    pub cid_integrity: u32,
    pub audit_coverage: u32,
    pub access_control: u32,
    pub evidence_quality: u32,
    pub claim_coverage: u32,
    pub temporal_freshness: u32,
    pub contradiction_score: u32,
    pub source_credibility: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgmentResult {
    pub score: u32,
    pub grade: String,
    pub explanation: String,
    pub dimensions: JudgmentDimensions,
    pub weighted: JudgmentWeighted,
    pub operations_analyzed: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct JudgmentConfig {
    pub weights: [f64; 8],
    pub decay_half_life_ms: f64,
    pub min_operations: usize,
}

impl Default for JudgmentConfig {
    fn default() -> Self {
        Self { weights: [1.0; 8], decay_half_life_ms: 3_600_000.0, min_operations: 1 }
    }
}

impl JudgmentConfig {
    pub fn medical() -> Self {
        Self {
            weights: [1.2, 1.5, 1.0, 1.8, 1.5, 0.8, 1.5, 1.0],
            decay_half_life_ms: 86_400_000.0,
            min_operations: 1,
        }
    }
    pub fn financial() -> Self {
        Self {
            weights: [1.2, 1.8, 1.5, 1.0, 1.0, 1.2, 1.3, 1.0],
            decay_half_life_ms: 300_000.0,
            min_operations: 1,
        }
    }
}

pub struct JudgmentEngine;

impl JudgmentEngine {
    pub fn judge(kernel: &MemoryKernel, claims: Option<&ClaimSet>, config: &JudgmentConfig) -> JudgmentResult {
        let mut warnings = Vec::new();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let audit = kernel.audit_log();
        let agents = kernel.agents();
        let total_ops = audit.len();
        let packet_count = kernel.packet_count();

        if total_ops < config.min_operations {
            warnings.push(format!("Only {} ops (min {})", total_ops, config.min_operations));
        }

        // D1: CID integrity
        let cid_integrity = if packet_count > 0 {
            let ok_writes = audit.iter()
                .filter(|e| e.operation == MemoryKernelOp::MemWrite && e.outcome == OpOutcome::Success)
                .count();
            if ok_writes > 0 { 1.0 } else { 0.0 }
        } else { 0.5 };

        // D2: Audit coverage
        let audit_coverage = if total_ops > 0 {
            let agent_ops = agents.values().map(|a| a.total_packets as usize).sum::<usize>().max(1);
            (total_ops as f64 / (agent_ops as f64 + total_ops as f64) * 2.0).min(1.0)
        } else { 0.0 };

        // D3: Access control
        let access_control = if total_ops > 0 {
            let denied = audit.iter().filter(|e| e.outcome == OpOutcome::Denied).count();
            if agents.len() > 1 && denied > 0 { 1.0 }
            else if agents.len() > 1 { 0.7 }
            else { 0.8 }
        } else { 0.0 };

        // D4: Evidence quality (from claims)
        let evidence_quality = claims.map(|cs| {
            let t = cs.total(); if t > 0 { cs.confirmed_count() as f64 / t as f64 } else { 0.5 }
        }).unwrap_or(0.5);

        // D5: Claim coverage
        let claim_coverage = claims.map(|cs| {
            let t = cs.total();
            if t > 0 { (cs.confirmed_count() + cs.needs_review_count()) as f64 / t as f64 } else { 0.5 }
        }).unwrap_or(0.5);

        // D6: Temporal freshness (exponential decay)
        let temporal_freshness = if packet_count > 0 {
            let most_recent = audit.iter()
                .filter(|e| e.operation == MemoryKernelOp::MemWrite && e.outcome == OpOutcome::Success)
                .map(|e| e.timestamp).max().unwrap_or(0);
            if most_recent > 0 {
                let age = (now_ms - most_recent).max(0) as f64;
                (-age / config.decay_half_life_ms * std::f64::consts::LN_2).exp().max(0.1)
            } else { 0.5 }
        } else { 0.5 };

        // D7: Contradiction score (1.0 = no contradictions)
        let contradiction_score = claims.map(|cs| {
            let t = cs.total();
            if t > 0 { (1.0 - cs.rejected_count() as f64 / t as f64).max(0.0) } else { 1.0 }
        }).unwrap_or(1.0);

        // D8: Source credibility
        let source_credibility = if agents.len() > 0 {
            let with_roles = agents.values()
                .filter(|a| a.agent_role.is_some() || a.role != AgentRole::Writer)
                .count();
            (0.5 + with_roles as f64 / agents.len() as f64 * 0.5).min(1.0)
        } else { 0.3 };

        // Weighted scoring
        let raw = [cid_integrity, audit_coverage, access_control, evidence_quality,
                    claim_coverage, temporal_freshness, contradiction_score, source_credibility];
        let tw: f64 = config.weights.iter().sum();
        let ws: Vec<f64> = raw.iter().zip(config.weights.iter())
            .map(|(r, w)| r * w * 20.0 / tw * 8.0).collect();
        let score = (ws.iter().sum::<f64>().round() as u32).min(100);

        let weighted = JudgmentWeighted {
            cid_integrity: (ws[0].round() as u32).min(20),
            audit_coverage: (ws[1].round() as u32).min(20),
            access_control: (ws[2].round() as u32).min(20),
            evidence_quality: (ws[3].round() as u32).min(20),
            claim_coverage: (ws[4].round() as u32).min(20),
            temporal_freshness: (ws[5].round() as u32).min(20),
            contradiction_score: (ws[6].round() as u32).min(20),
            source_credibility: (ws[7].round() as u32).min(20),
        };

        let names = ["CID integrity","audit","access","evidence","coverage",
                      "freshness","contradictions","credibility"];
        let weakest = raw.iter().enumerate()
            .min_by(|a,b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i,_)| i).unwrap_or(0);
        let grade = match score { 90..=100=>"A+", 80..=89=>"A", 70..=79=>"B", 60..=69=>"C", 40..=59=>"D", _=>"F" };
        let explanation = format!("{}/100 — weakest: {} ({:.0}%)", score, names[weakest], raw[weakest]*100.0);

        if evidence_quality < 0.3 { warnings.push("Low evidence quality".into()); }
        if temporal_freshness < 0.3 { warnings.push("Stale data".into()); }
        if contradiction_score < 0.5 { warnings.push("High contradiction rate".into()); }

        JudgmentResult {
            score, grade: grade.to_string(), explanation,
            dimensions: JudgmentDimensions {
                cid_integrity, audit_coverage, access_control, evidence_quality,
                claim_coverage, temporal_freshness, contradiction_score, source_credibility,
            },
            weighted, operations_analyzed: total_ops, warnings,
        }
    }

    pub fn judge_kernel(kernel: &MemoryKernel) -> JudgmentResult {
        Self::judge(kernel, None, &JudgmentConfig::default())
    }
    pub fn judge_medical(kernel: &MemoryKernel, claims: &ClaimSet) -> JudgmentResult {
        Self::judge(kernel, Some(claims), &JudgmentConfig::medical())
    }
    pub fn judge_financial(kernel: &MemoryKernel, claims: &ClaimSet) -> JudgmentResult {
        Self::judge(kernel, Some(claims), &JudgmentConfig::financial())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{SyscallRequest, SyscallPayload, SyscallValue};

    fn setup() -> (MemoryKernel, String) {
        let mut k = MemoryKernel::new();
        let r = k.dispatch(SyscallRequest {
            agent_pid: "system".into(), operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "bot".into(), namespace: "ns:bot".into(),
                role: Some("writer".into()), model: None, framework: None,
            }, reason: None, vakya_id: None,
        });
        let pid = match r.value { SyscallValue::AgentPid(p) => p, _ => panic!() };
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(), operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty, reason: None, vakya_id: None,
        });
        (k, pid)
    }

    fn write_packet(k: &mut MemoryKernel, pid: &str, text: &str) {
        let pkt = MemPacket::new(
            PacketType::Input, serde_json::json!({"text": text}), cid::Cid::default(),
            "user:test".into(), "pipe:test".into(),
            Source { kind: SourceKind::User, principal_id: "user:test".into() },
            chrono::Utc::now().timestamp_millis(),
        );
        k.dispatch(SyscallRequest {
            agent_pid: pid.into(), operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: pkt }, reason: None, vakya_id: None,
        });
    }

    #[test]
    fn test_judgment_basic() {
        let (mut k, pid) = setup();
        write_packet(&mut k, &pid, "hello");
        write_packet(&mut k, &pid, "world");
        let j = JudgmentEngine::judge_kernel(&k);
        assert!(j.score > 0);
        assert!(!j.grade.is_empty());
        assert!(j.operations_analyzed > 0);
    }

    #[test]
    fn test_judgment_empty_kernel() {
        let k = MemoryKernel::new();
        let j = JudgmentEngine::judge_kernel(&k);
        // Empty kernel: no ops, neutral dims at 0.5, some at 0.0/0.3
        assert!(j.score <= 80, "Empty kernel score should be moderate, got {}", j.score);
        assert!(j.operations_analyzed == 0);
    }

    #[test]
    fn test_judgment_medical_config() {
        let (mut k, pid) = setup();
        for i in 0..10 { write_packet(&mut k, &pid, &format!("data {}", i)); }
        let j = JudgmentEngine::judge(&k, None, &JudgmentConfig::medical());
        assert!(j.score > 0);
        assert!(!j.explanation.is_empty());
    }

    #[test]
    fn test_judgment_with_claims() {
        let (mut k, pid) = setup();
        write_packet(&mut k, &pid, "patient has chest pain and fever");
        let claims = vec![
            crate::claims::Claim {
                item: "chest pain".into(), category: "symptoms".into(),
                evidence: crate::claims::Evidence {
                    source_cid: "cid:test".into(), field_path: None,
                    quote: "chest pain".into(),
                    support: crate::claims::SupportLevel::Explicit,
                }, code: Some("R07.9".into()), code_desc: Some("Chest pain".into()),
            },
            crate::claims::Claim {
                item: "fever".into(), category: "symptoms".into(),
                evidence: crate::claims::Evidence {
                    source_cid: "cid:test".into(), field_path: None,
                    quote: "fever".into(),
                    support: crate::claims::SupportLevel::Explicit,
                }, code: Some("R50.9".into()), code_desc: Some("Fever".into()),
            },
            crate::claims::Claim {
                item: "diabetes".into(), category: "conditions".into(),
                evidence: crate::claims::Evidence {
                    source_cid: "cid:test".into(), field_path: None,
                    quote: "diabetes".into(),
                    support: crate::claims::SupportLevel::Absent,
                }, code: None, code_desc: None,
            },
        ];
        let cs = crate::claims::ClaimVerifier::verify(&claims, "patient has chest pain and fever", "cid:test");
        let j = JudgmentEngine::judge(&k, Some(&cs), &JudgmentConfig::default());
        // chest pain + fever confirmed, diabetes rejected → mixed
        assert!(j.dimensions.evidence_quality > 0.0, "Should have some confirmed claims");
        assert!(j.dimensions.contradiction_score < 1.0, "Should have some rejected claims");
    }

    #[test]
    fn test_judgment_dimensions_range() {
        let (mut k, pid) = setup();
        for i in 0..5 { write_packet(&mut k, &pid, &format!("pkt {}", i)); }
        let j = JudgmentEngine::judge_kernel(&k);
        let d = &j.dimensions;
        assert!(d.cid_integrity >= 0.0 && d.cid_integrity <= 1.0);
        assert!(d.audit_coverage >= 0.0 && d.audit_coverage <= 1.0);
        assert!(d.temporal_freshness >= 0.0 && d.temporal_freshness <= 1.0);
        assert!(d.source_credibility >= 0.0 && d.source_credibility <= 1.0);
    }
}
