//! # Cognitive Substrate
//!
//! The structured internal universe in which agents think, plan, reason, and commit.
//! Sits **beneath** the LLM and **above** the memory kernel.
//!
//! ## Architecture
//!
//! 11-layer pipeline from perception to reflection:
//!
//! | Layer | Module | Function |
//! |-------|--------|----------|
//! | 0 | `types::PerceptionObject` | Raw input from world |
//! | 1 | `types::MeaningObject` | Semantic classification |
//! | 2 | `tension` | Unresolved cognitive pressure |
//! | 3 | `types::ActiveKnowledgeSet` | Activated knowledge forms |
//! | 4 | `possibility` | Candidate state transformations |
//! | 5 | `evaluation` | Multi-dimensional scoring |
//! | 6 | `expertise` | Domain-specific pruning & weighting |
//! | 7 | `commitment` | Adopted working truths & actions |
//! | 8 | `plan` | Commitment DAG with temporal ordering |
//! | 9 | `exposure` | Multi-audience explanation rendering |
//! | 10 | `reflection` | Expected vs actual comparison |
//!
//! ## Design Principles
//!
//! 1. **Thought is not language** — operates on typed objects, not strings
//! 2. **No tension, no thought** — cognition is driven by unresolved pressure
//! 3. **Possibilities are the center** — intelligence = navigating possibility space
//! 4. **Expertise is runtime** — pluggable domain evaluators, not prompt styles
//! 5. **Commitments persist** — survive across cycles, constrain future planning
//! 6. **Evidence everywhere** — every object references CIDs
//! 7. **Recovery by default** — checkpoints at every layer transition

pub mod types;
pub mod tension;
pub mod possibility;
pub mod evaluation;
pub mod expertise;
pub mod commitment;
pub mod plan;
pub mod exposure;
pub mod reflection;
pub mod checkpoint;
pub mod cycle;

// ── Re-exports ─────────────────────────────────────────────────────────

// Core types
pub use types::{
    PerceptionObject, PerceptionSource, Modality,
    MeaningObject, MeaningType, Urgency, Severity,
    Tension, TensionType, TensionResolution, TensionGraph, TensionEdge, TensionRelation,
    KnowledgeForm, NormativeEnforcement, ActivatedKnowledge, ActiveKnowledgeSet,
    Possibility, PossibilityType, Precondition, Reversibility, PolicyStatus, Cost,
    PossibilityEvaluation, EvaluationScores, EvaluationWeights, EvalRecommendation,
    ExpertiseEvaluation, Antipattern,
    Commitment, CommitmentType, CommitmentStrength, CommitmentStatus,
    CommitmentRegister, CommitmentEdge, CommitmentRelation,
    CognitivePlan, PlanNode, PlanNodeStatus, PlanEdge, PlanEdgeType,
    Explanation, ExplanationAudience, ExplanationDepth, ExplanationSection,
    ReflectionRecord, ReflectionComparison, Significance, ReflectionAssessment,
    TensionUpdate, TensionUpdateType,
    ThoughtRecord, ThoughtSeed, TriggerType,
    ThoughtCheckpoint, ThoughtCheckpointState,
    CognitiveMessage, CognitiveMessageType,
    CognitiveContext,
};

// Engines
pub use tension::TensionEngine;
pub use possibility::PossibilityGenerator;
pub use evaluation::EvaluationEngine;
pub use expertise::{ExpertiseKernel, GeneralExpertiseKernel, MedicalExpertiseKernel, ExpertiseRegistry};
pub use commitment::CommitmentEngine;
pub use plan::PlanEngine;
pub use exposure::ExposureEngine;
pub use reflection::ReflectionEngine;
pub use checkpoint::CheckpointManager;
pub use cycle::{CognitiveSubstrate, CognitiveCycleResult, CycleConfig};
