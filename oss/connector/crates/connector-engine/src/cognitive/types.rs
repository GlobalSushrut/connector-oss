//! # Cognitive Substrate — Core Type System
//!
//! Every type here is a first-class ontological object, not a string wrapper.
//! These are the primitives of thought: perception, meaning, tension, knowledge,
//! possibility, evaluation, commitment, plan, explanation, reflection.
//!
//! Design principle: Thought is not language. Language is one rendering of thought.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────
// Layer 0 — Perception Objects
// ─────────────────────────────────────────────────────────────

/// Raw signal from the external world, not yet cognitively processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerceptionObject {
    pub id: String,
    pub source: PerceptionSource,
    pub modality: Modality,
    pub raw_content: serde_json::Value,
    pub timestamp: i64,
    pub evidence_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PerceptionSource {
    UserInput,
    ToolOutput,
    MemoryRecall,
    SensorData,
    PeerAgentMessage { agent_pid: String },
    SystemEvent,
    EnvironmentObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Modality {
    Text,
    Structured,
    Numeric,
    Visual,
    Audio,
    Spatial,
    Multimodal,
}

// ─────────────────────────────────────────────────────────────
// Layer 1 — Meaning Objects
// ─────────────────────────────────────────────────────────────

/// A perception that has been semantically classified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeaningObject {
    pub id: String,
    pub source_perception: String,
    pub meaning_type: MeaningType,
    pub entities: Vec<String>,
    /// 0.0–1.0, how relevant to current context
    pub salience: f64,
    /// 0.0–1.0, how certain we are of classification
    pub confidence: f64,
    pub evidence_cids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeaningType {
    Request { intent: String, urgency: Urgency },
    Anomaly { expected: String, observed: String },
    Requirement { constraint: String },
    Contradiction { claim_a: String, claim_b: String },
    Unknown { description: String },
    Opportunity { potential: String },
    Risk { threat: String, severity: Severity },
    Dependency { on: String },
    Confirmation { of: String },
    Correction { from: String, to: String },
    Information { topic: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Urgency {
    Critical,
    High,
    Normal,
    Low,
    Background,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Negligible,
}

// ─────────────────────────────────────────────────────────────
// Layer 2 — Tension Graph
// ─────────────────────────────────────────────────────────────

/// Unresolved cognitive pressure that drives thought.
/// No tension → no need for cognition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tension {
    pub id: String,
    pub tension_type: TensionType,
    pub source_meanings: Vec<String>,
    /// 0.0–1.0 intensity
    pub intensity: f64,
    pub created_at: i64,
    /// When must this be resolved?
    pub deadline: Option<i64>,
    pub resolution: TensionResolution,
    pub related_tensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TensionType {
    GoalGap { current: String, desired: String },
    DataMissing { what: String, why_needed: String },
    PolicyConflict { policy_a: String, policy_b: String },
    Ambiguity { interpretations: Vec<String> },
    RiskTooHigh { risk: String, threshold: f64, actual: f64 },
    ContradictionDetected { claim_a: String, claim_b: String },
    ResourceConstrained { resource: String, available: f64, needed: f64 },
    TimeoutPressure { deadline: i64 },
    TrustDeficit { entity: String, required: f64, actual: f64 },
    ExpertiseGap { domain: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TensionResolution {
    Unresolved,
    Resolving { by_commitment: String },
    Resolved { by_commitment: String, at: i64 },
    Abandoned { reason: String },
    Escalated { to: String },
}

/// The graph of all active tensions and their relationships.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TensionGraph {
    pub tensions: HashMap<String, Tension>,
    pub edges: Vec<TensionEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensionEdge {
    pub from: String,
    pub to: String,
    pub relation: TensionRelation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TensionRelation {
    Causes,
    Blocks,
    Amplifies,
    Mitigates,
    DependsOn,
}

// ─────────────────────────────────────────────────────────────
// Layer 3 — Knowledge Ontology
// ─────────────────────────────────────────────────────────────

/// The eight forms of knowledge, each a first-class type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KnowledgeForm {
    /// Facts, definitions, world truths. "X is Y."
    Declarative {
        entity: String,
        attribute: String,
        value: serde_json::Value,
        confidence: f64,
        source_cids: Vec<String>,
    },
    /// How to do things. "If condition A, perform sequence B."
    Procedural {
        name: String,
        preconditions: Vec<String>,
        steps: Vec<String>,
        postconditions: Vec<String>,
        success_rate: f64,
    },
    /// How things relate. "System A depends on B and constrains C."
    Structural {
        from: String,
        relation: String,
        to: String,
        weight: f64,
    },
    /// Why things happen. "If this changes, that likely changes."
    Causal {
        cause: String,
        effect: String,
        strength: f64,
        conditions: Vec<String>,
    },
    /// How to choose among possible paths.
    Strategic {
        context: String,
        strategy: String,
        expected_utility: f64,
        risk: f64,
    },
    /// What is allowed, desired, safe, ethical, legal.
    Normative {
        rule: String,
        domain: String,
        enforcement: NormativeEnforcement,
    },
    /// What worked before, what failed before.
    Experiential {
        situation: String,
        action_taken: String,
        outcome: String,
        lesson: String,
        success: bool,
    },
    /// What the system knows it does NOT know.
    Meta {
        topic: String,
        gap_description: String,
        importance: f64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NormativeEnforcement {
    Hard,
    Soft,
    Advisory,
}

/// Activated knowledge — what's relevant right now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivatedKnowledge {
    pub form: KnowledgeForm,
    /// Recency × frequency × context match
    pub activation: f64,
    pub source_cids: Vec<String>,
}

/// Complete set of activated knowledge for a cognitive cycle.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActiveKnowledgeSet {
    pub knowledge: Vec<ActivatedKnowledge>,
    pub total_activation: f64,
    pub token_budget_used: usize,
}

// ─────────────────────────────────────────────────────────────
// Layer 4 — Possibility Field
// ─────────────────────────────────────────────────────────────

/// A candidate transformation of state that could be made real.
/// This is the CENTER of intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Possibility {
    pub id: String,
    pub possibility_type: PossibilityType,
    pub description: String,
    pub preconditions: Vec<Precondition>,
    pub required_knowledge: Vec<String>,
    pub expected_value: f64,
    pub risk: f64,
    pub reversibility: Reversibility,
    pub dependencies: Vec<String>,
    pub policy_status: PolicyStatus,
    pub estimated_confidence: f64,
    pub estimated_cost: Cost,
    pub source_tensions: Vec<String>,
    pub evaluation: Option<PossibilityEvaluation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PossibilityType {
    Infer { from: Vec<String>, conclusion: String },
    Ask { question: String, target: String },
    Retrieve { query: String, from: String },
    Simulate { scenario: String },
    Verify { claim: String, method: String },
    Decompose { problem: String, into: Vec<String> },
    Act { action: String, target: String },
    Wait { for_event: String, timeout_ms: u64 },
    Escalate { to: String, reason: String },
    Reject { what: String, reason: String },
    Delegate { to_agent: String, task: String },
    Plan { goal: String, approach: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precondition {
    pub description: String,
    pub met: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reversibility {
    FullyReversible,
    PartiallyReversible,
    Irreversible,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyStatus {
    Allowed,
    Forbidden,
    RequiresApproval,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Cost {
    pub tokens: u64,
    pub time_ms: u64,
    pub monetary: f64,
}

// ─────────────────────────────────────────────────────────────
// Layer 5 — Evaluation
// ─────────────────────────────────────────────────────────────

/// Evaluation of a possibility across multiple dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PossibilityEvaluation {
    pub possibility_id: String,
    pub scores: EvaluationScores,
    pub rank: usize,
    pub recommendation: EvalRecommendation,
    pub justification: String,
    /// Which expertise kernels contributed
    pub evaluated_by: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct EvaluationScores {
    /// Does this fit with current beliefs?
    pub coherence: f64,
    /// How much value does it produce?
    pub utility: f64,
    /// How expensive is it? (lower = better)
    pub cost: f64,
    /// Is it policy-compliant?
    pub legality: f64,
    /// Is there sufficient evidence?
    pub evidence: f64,
    /// Can we undo it?
    pub reversibility: f64,
    /// Do we trust the sources?
    pub trust: f64,
    /// Does timing match tension deadline?
    pub urgency_fit: f64,
}

impl EvaluationScores {
    /// Weighted composite score. Weights can be tuned per domain.
    pub fn composite(&self, weights: &EvaluationWeights) -> f64 {
        self.coherence * weights.coherence
            + self.utility * weights.utility
            - self.cost * weights.cost
            + self.legality * weights.legality
            + self.evidence * weights.evidence
            + self.reversibility * weights.reversibility
            + self.trust * weights.trust
            + self.urgency_fit * weights.urgency_fit
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EvaluationWeights {
    pub coherence: f64,
    pub utility: f64,
    pub cost: f64,
    pub legality: f64,
    pub evidence: f64,
    pub reversibility: f64,
    pub trust: f64,
    pub urgency_fit: f64,
}

impl Default for EvaluationWeights {
    fn default() -> Self {
        Self {
            coherence: 0.15,
            utility: 0.25,
            cost: 0.10,
            legality: 0.15,
            evidence: 0.10,
            reversibility: 0.05,
            trust: 0.10,
            urgency_fit: 0.10,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvalRecommendation {
    StrongCommit,
    Commit,
    Tentative,
    Defer,
    Reject,
}

// ─────────────────────────────────────────────────────────────
// Layer 6 — Expertise
// ─────────────────────────────────────────────────────────────

/// Result of a domain-specific evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertiseEvaluation {
    pub domain: String,
    pub domain_score: f64,
    pub domain_warnings: Vec<String>,
    pub pruned: bool,
    pub reason: String,
}

/// Known trap in a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Antipattern {
    pub name: String,
    pub description: String,
    pub detection: String,
    pub remedy: String,
}

// ─────────────────────────────────────────────────────────────
// Layer 7 — Commitment
// ─────────────────────────────────────────────────────────────

/// A commitment the system has adopted as working truth or action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    pub id: String,
    pub commitment_type: CommitmentType,
    pub content: String,
    pub strength: CommitmentStrength,
    pub justification: Vec<String>,
    pub source_possibilities: Vec<String>,
    pub source_tensions: Vec<String>,
    pub revisable: bool,
    pub revision_conditions: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub status: CommitmentStatus,
    pub evidence_cids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitmentType {
    Belief { proposition: String },
    Goal { desired_state: String },
    Plan { plan_id: String },
    Action { action_id: String },
    Delegation { to_agent: String },
    Assumption { assumption: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitmentStrength {
    Hypothetical = 0,
    Tentative = 1,
    Working = 2,
    Strong = 3,
    Absolute = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommitmentStatus {
    Active,
    Executed,
    Revised { by: String },
    Abandoned { reason: String },
    Expired,
}

/// All active commitments for an agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommitmentRegister {
    pub commitments: HashMap<String, Commitment>,
    pub commitment_graph: Vec<CommitmentEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentEdge {
    pub from: String,
    pub to: String,
    pub relation: CommitmentRelation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommitmentRelation {
    DependsOn,
    Contradicts,
    Strengthens,
    Refines,
    Replaces,
}

// ─────────────────────────────────────────────────────────────
// Layer 8 — Plan as Commitment DAG
// ─────────────────────────────────────────────────────────────

/// A plan is a temporally ordered commitment structure.
/// NOT a flat step list — a DAG of committed possibilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitivePlan {
    pub id: String,
    /// Which tension does this plan resolve?
    pub goal_tension: String,
    pub nodes: Vec<PlanNode>,
    pub edges: Vec<PlanEdge>,
    /// Nodes ready to execute
    pub current_frontier: Vec<String>,
    /// The commitment that adopted this plan
    pub commitment_id: String,
    pub revision_count: u32,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanNode {
    pub id: String,
    /// The possibility this node commits to
    pub possibility: Possibility,
    /// Commitment for this specific step
    pub commitment_id: Option<String>,
    pub status: PlanNodeStatus,
    pub result: Option<serde_json::Value>,
    pub evidence_cids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PlanNodeStatus {
    Pending,
    Ready,
    Executing,
    Completed,
    Failed { reason: String },
    Skipped { reason: String },
    Revised { replacement: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEdge {
    pub from: String,
    pub to: String,
    pub edge_type: PlanEdgeType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PlanEdgeType {
    DependsOn,
    Parallel,
    Fallback,
    Conditional { condition: String },
}

// ─────────────────────────────────────────────────────────────
// Layer 9 — Exposure / Explanation
// ─────────────────────────────────────────────────────────────

/// Render thought substrate for a target audience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explanation {
    pub target_audience: ExplanationAudience,
    pub depth: ExplanationDepth,
    pub sections: Vec<ExplanationSection>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExplanationAudience {
    Human,
    PeerAgent,
    AuditTrail,
    Debugger,
    ComplianceOfficer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExplanationDepth {
    Summary,
    Standard,
    Detailed,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationSection {
    pub title: String,
    pub content: String,
    pub evidence_cids: Vec<String>,
    pub related_tensions: Vec<String>,
    pub related_commitments: Vec<String>,
}

// ─────────────────────────────────────────────────────────────
// Layer 10 — Reflection
// ─────────────────────────────────────────────────────────────

/// Post-action comparison: expected vs actual, intended vs observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionRecord {
    pub id: String,
    pub commitment_id: String,
    pub comparisons: Vec<ReflectionComparison>,
    pub learning_delta: Vec<KnowledgeForm>,
    pub plan_revisions: Vec<String>,
    pub tension_updates: Vec<TensionUpdate>,
    pub overall_assessment: ReflectionAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionComparison {
    pub dimension: String,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub delta: f64,
    pub significance: Significance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Significance {
    Critical,
    Significant,
    Minor,
    Negligible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReflectionAssessment {
    AsExpected,
    BetterThanExpected { delta: f64 },
    WorseThanExpected { delta: f64, corrective: Option<String> },
    CompletelyWrong { root_cause: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensionUpdate {
    pub tension_id: String,
    pub update_type: TensionUpdateType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TensionUpdateType {
    Resolved,
    Intensified { new_intensity: f64 },
    Transformed { into_tension: String },
    New,
}

// ─────────────────────────────────────────────────────────────
// Thought Record — complete snapshot
// ─────────────────────────────────────────────────────────────

/// Complete thought record — stored in VAC as CID-backed MemPacket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtRecord {
    pub id: String,
    pub agent_pid: String,
    pub cycle_number: u32,
    pub timestamp: i64,

    pub seed: ThoughtSeed,
    pub tensions: Vec<Tension>,
    pub active_knowledge: ActiveKnowledgeSet,
    pub possibility_set: Vec<Possibility>,
    pub evaluations: Vec<PossibilityEvaluation>,
    pub commitments: Vec<Commitment>,
    pub plan: Option<CognitivePlan>,
    pub reflection: Option<ReflectionRecord>,

    /// CID chain for tamper-proof history
    pub prev_thought_cid: Option<String>,
    pub thought_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtSeed {
    pub trigger_type: TriggerType,
    pub perception_ids: Vec<String>,
    pub meaning_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TriggerType {
    UserRequest,
    ToolResult,
    PeerMessage,
    TensionThreshold,
    ScheduledReview,
    ExternalEvent,
    ReflectionTriggered,
}

// ─────────────────────────────────────────────────────────────
// Thought Checkpoint — for recovery
// ─────────────────────────────────────────────────────────────

/// Thought checkpoint — saved at each layer transition.
/// If a cycle fails, recovery starts from the last checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtCheckpoint {
    pub checkpoint_id: String,
    pub agent_pid: String,
    pub cycle_number: u32,
    pub layer: u8,
    pub timestamp: i64,
    pub state: ThoughtCheckpointState,
    pub cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThoughtCheckpointState {
    pub meanings: Vec<MeaningObject>,
    pub tensions: TensionGraph,
    pub active_knowledge: Option<ActiveKnowledgeSet>,
    pub possibilities: Vec<Possibility>,
    pub evaluations: Vec<PossibilityEvaluation>,
    pub commitments: CommitmentRegister,
    pub plan: Option<CognitivePlan>,
}

// ─────────────────────────────────────────────────────────────
// Cognitive Message — inter-agent thought exchange
// ─────────────────────────────────────────────────────────────

/// A message between agents that carries cognitive state, not just text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveMessage {
    pub message_id: String,
    pub from_agent: String,
    pub to_agent: String,
    pub message_type: CognitiveMessageType,
    pub timestamp: i64,
    pub evidence_cid: Option<String>,
    pub reply_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CognitiveMessageType {
    /// Share a tension that needs collaborative resolution
    ShareTension {
        tension: Tension,
        context: Vec<MeaningObject>,
    },
    /// Share a commitment for coordination
    ShareCommitment {
        commitment: Commitment,
        plan_fragment: Option<CognitivePlan>,
    },
    /// Request knowledge from peer
    KnowledgeRequest {
        topic: String,
        knowledge_forms: Vec<String>,
    },
    /// Provide knowledge to peer
    KnowledgeResponse {
        knowledge: Vec<KnowledgeForm>,
        source_cids: Vec<String>,
    },
    /// Share evaluation of a possibility
    ShareEvaluation {
        possibility_id: String,
        evaluation: PossibilityEvaluation,
    },
    /// Request plan coordination
    PlanCoordination {
        plan_id: String,
        requested_action: String,
    },
    /// Report reflection results
    ReflectionReport {
        reflection: ReflectionRecord,
    },
    /// Raw text (backward-compatible)
    Text {
        content: String,
    },
}

// ─────────────────────────────────────────────────────────────
// Cognitive Context — passed through layers
// ─────────────────────────────────────────────────────────────

/// Shared context passed through all cognitive layers during a cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveContext {
    pub agent_pid: String,
    pub namespace: String,
    pub cycle_number: u32,
    pub token_budget: usize,
    pub deadline: Option<i64>,
    pub active_commitments: CommitmentRegister,
    pub evaluation_weights: EvaluationWeights,
    pub max_possibilities: usize,
    pub max_plan_depth: usize,
}

impl Default for CognitiveContext {
    fn default() -> Self {
        Self {
            agent_pid: String::new(),
            namespace: String::new(),
            cycle_number: 0,
            token_budget: 4096,
            deadline: None,
            active_commitments: CommitmentRegister::default(),
            evaluation_weights: EvaluationWeights::default(),
            max_possibilities: 12,
            max_plan_depth: 5,
        }
    }
}
