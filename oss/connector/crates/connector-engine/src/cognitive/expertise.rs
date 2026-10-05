//! # Expertise Kernel
//!
//! Domain-specific evaluators that shape possibility generation, pruning,
//! and evaluation. Expertise is a runtime layer, not a prompt style.

use super::types::*;

/// A pluggable domain expertise kernel.
/// Each domain (medical, financial, legal, engineering, ...) implements this trait
/// to provide domain-specific reasoning capabilities.
pub trait ExpertiseKernel: Send + Sync {
    /// Domain identifier (e.g., "medical", "financial", "legal")
    fn domain(&self) -> &str;

    /// Domain-specific evaluator: score possibilities in this domain's terms.
    fn evaluate(&self, possibility: &Possibility, context: &CognitiveContext) -> ExpertiseEvaluation;

    /// Domain-specific pruning: which possibilities are obviously wrong?
    /// Returns IDs of possibilities to prune.
    fn prune(&self, possibilities: &[Possibility], context: &CognitiveContext) -> Vec<String>;

    /// Domain-specific confidence: what qualifies as "good enough" in this domain?
    fn confidence_threshold(&self) -> f64;

    /// Domain-specific failure patterns: known traps.
    fn known_antipatterns(&self) -> Vec<Antipattern>;

    /// Domain-specific procedural memory: best practices for a situation.
    fn best_practices(&self, situation: &str) -> Vec<KnowledgeForm>;
}

/// Default expertise kernel — general-purpose reasoning with no domain bias.
pub struct GeneralExpertiseKernel;

impl ExpertiseKernel for GeneralExpertiseKernel {
    fn domain(&self) -> &str {
        "general"
    }

    fn evaluate(&self, possibility: &Possibility, _context: &CognitiveContext) -> ExpertiseEvaluation {
        // General kernel: no domain-specific scoring, pass through
        ExpertiseEvaluation {
            domain: "general".into(),
            domain_score: possibility.estimated_confidence,
            domain_warnings: vec![],
            pruned: false,
            reason: "general-purpose evaluation".into(),
        }
    }

    fn prune(&self, possibilities: &[Possibility], _context: &CognitiveContext) -> Vec<String> {
        // Prune possibilities that are forbidden by policy
        possibilities
            .iter()
            .filter(|p| p.policy_status == PolicyStatus::Forbidden)
            .map(|p| p.id.clone())
            .collect()
    }

    fn confidence_threshold(&self) -> f64 {
        0.5
    }

    fn known_antipatterns(&self) -> Vec<Antipattern> {
        vec![
            Antipattern {
                name: "premature_commitment".into(),
                description: "Committing to action before sufficient evidence".into(),
                detection: "confidence < 0.3 AND commitment_strength > Working".into(),
                remedy: "Gather more evidence before committing".into(),
            },
            Antipattern {
                name: "analysis_paralysis".into(),
                description: "Generating too many possibilities without committing".into(),
                detection: "possibilities.len() > 20 AND commitments.len() == 0".into(),
                remedy: "Apply stronger pruning and commit to best available".into(),
            },
            Antipattern {
                name: "irreversible_without_evidence".into(),
                description: "Taking irreversible action without strong evidence".into(),
                detection: "reversibility == Irreversible AND evidence_score < 0.7".into(),
                remedy: "Require higher evidence threshold for irreversible actions".into(),
            },
        ]
    }

    fn best_practices(&self, _situation: &str) -> Vec<KnowledgeForm> {
        vec![]
    }
}

/// Medical domain expertise kernel.
pub struct MedicalExpertiseKernel;

impl ExpertiseKernel for MedicalExpertiseKernel {
    fn domain(&self) -> &str {
        "medical"
    }

    fn evaluate(&self, possibility: &Possibility, _context: &CognitiveContext) -> ExpertiseEvaluation {
        let mut warnings = Vec::new();
        let mut score = possibility.estimated_confidence;

        // Medical: irreversible actions require higher confidence
        if possibility.reversibility == Reversibility::Irreversible {
            if possibility.estimated_confidence < 0.9 {
                warnings.push("Medical: irreversible action requires ≥0.9 confidence".into());
                score *= 0.5;
            }
        }

        // Medical: high-risk possibilities need explicit evidence
        if possibility.risk > 0.7 {
            warnings.push("Medical: high-risk action flagged for review".into());
            score *= 0.7;
        }

        ExpertiseEvaluation {
            domain: "medical".into(),
            domain_score: score,
            domain_warnings: warnings,
            pruned: false,
            reason: "medical domain evaluation".into(),
        }
    }

    fn prune(&self, possibilities: &[Possibility], _context: &CognitiveContext) -> Vec<String> {
        let mut pruned = Vec::new();
        for p in possibilities {
            // Medical: never allow forbidden or unapproved irreversible actions
            if p.reversibility == Reversibility::Irreversible
                && p.policy_status != PolicyStatus::Allowed
            {
                pruned.push(p.id.clone());
            }
        }
        pruned
    }

    fn confidence_threshold(&self) -> f64 {
        0.8 // Medical requires higher confidence
    }

    fn known_antipatterns(&self) -> Vec<Antipattern> {
        vec![
            Antipattern {
                name: "diagnosis_without_differential".into(),
                description: "Committing to a diagnosis without considering alternatives".into(),
                detection: "commitment_type == Belief AND possibilities.len() < 3".into(),
                remedy: "Generate at least 3 differential diagnoses before committing".into(),
            },
            Antipattern {
                name: "treatment_before_diagnosis".into(),
                description: "Proposing treatment without confirmed diagnosis".into(),
                detection: "possibility_type == Act AND no Belief commitment exists".into(),
                remedy: "Establish diagnostic commitment before treatment planning".into(),
            },
        ]
    }

    fn best_practices(&self, situation: &str) -> Vec<KnowledgeForm> {
        let mut practices = Vec::new();
        if situation.contains("diagnos") {
            practices.push(KnowledgeForm::Procedural {
                name: "differential_diagnosis".into(),
                preconditions: vec!["patient symptoms observed".into()],
                steps: vec![
                    "List all symptoms".into(),
                    "Generate ≥3 differential diagnoses".into(),
                    "Order by likelihood".into(),
                    "Identify distinguishing tests".into(),
                    "Recommend most informative test first".into(),
                ],
                postconditions: vec!["ranked differential with test plan".into()],
                success_rate: 0.85,
            });
        }
        practices
    }
}

/// Expertise registry — manages all active expertise kernels.
pub struct ExpertiseRegistry {
    kernels: Vec<Box<dyn ExpertiseKernel>>,
}

impl ExpertiseRegistry {
    pub fn new() -> Self {
        Self {
            kernels: vec![Box::new(GeneralExpertiseKernel)],
        }
    }

    pub fn register(&mut self, kernel: Box<dyn ExpertiseKernel>) {
        self.kernels.push(kernel);
    }

    pub fn evaluate_all(
        &self,
        possibility: &Possibility,
        context: &CognitiveContext,
    ) -> Vec<ExpertiseEvaluation> {
        self.kernels
            .iter()
            .map(|k| k.evaluate(possibility, context))
            .collect()
    }

    pub fn prune_all(
        &self,
        possibilities: &[Possibility],
        context: &CognitiveContext,
    ) -> Vec<String> {
        let mut pruned = Vec::new();
        for k in &self.kernels {
            pruned.extend(k.prune(possibilities, context));
        }
        pruned.sort();
        pruned.dedup();
        pruned
    }

    pub fn domains(&self) -> Vec<&str> {
        self.kernels.iter().map(|k| k.domain()).collect()
    }

    pub fn best_confidence_threshold(&self) -> f64 {
        self.kernels
            .iter()
            .map(|k| k.confidence_threshold())
            .fold(0.0_f64, f64::max)
    }
}

impl Default for ExpertiseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_possibility(id: &str, confidence: f64, reversibility: Reversibility) -> Possibility {
        Possibility {
            id: id.into(),
            possibility_type: PossibilityType::Act {
                action: "test".into(),
                target: "target".into(),
            },
            description: "test possibility".into(),
            preconditions: vec![],
            required_knowledge: vec![],
            expected_value: 0.5,
            risk: 0.3,
            reversibility,
            dependencies: vec![],
            policy_status: PolicyStatus::Allowed,
            estimated_confidence: confidence,
            estimated_cost: Cost::default(),
            source_tensions: vec![],
            evaluation: None,
        }
    }

    #[test]
    fn test_general_kernel_prunes_forbidden() {
        let kernel = GeneralExpertiseKernel;
        let mut p = make_possibility("p1", 0.8, Reversibility::FullyReversible);
        p.policy_status = PolicyStatus::Forbidden;
        let ctx = CognitiveContext::default();
        let pruned = kernel.prune(&[p], &ctx);
        assert_eq!(pruned, vec!["p1"]);
    }

    #[test]
    fn test_medical_kernel_penalizes_low_confidence_irreversible() {
        let kernel = MedicalExpertiseKernel;
        let p = make_possibility("p2", 0.5, Reversibility::Irreversible);
        let ctx = CognitiveContext::default();
        let eval = kernel.evaluate(&p, &ctx);
        assert!(eval.domain_score < 0.5);
        assert!(!eval.domain_warnings.is_empty());
    }

    #[test]
    fn test_registry_combines_evaluations() {
        let mut registry = ExpertiseRegistry::new();
        registry.register(Box::new(MedicalExpertiseKernel));
        let p = make_possibility("p3", 0.7, Reversibility::FullyReversible);
        let ctx = CognitiveContext::default();
        let evals = registry.evaluate_all(&p, &ctx);
        assert_eq!(evals.len(), 2); // general + medical
    }
}
