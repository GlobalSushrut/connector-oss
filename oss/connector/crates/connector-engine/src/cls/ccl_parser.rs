//! CCL Parser — recursive descent parser producing a typed AST.
//!
//! Implements the parser specified in CONNECTOR_CONTRACT_LANGUAGE.md §9.
//! Features:
//!   - LL(1) recursive descent with fallback
//!   - Full AST with Span on every node
//!   - Error recovery via synchronization points
//!   - Predicate precedence climbing (or < and < not < comparisons < field access)

use crate::cls::ccl_lexer::{Token, TokenKind, Span, Pos, LexError, CclLexer};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// AST Node Types
// ═══════════════════════════════════════════════════════════════

/// Root of the AST — a single contract definition.
#[derive(Debug, Clone)]
pub struct ContractNode {
    pub name: String,
    pub blocks: Vec<BlockNode>,
    pub span: Span,
}

/// Top-level blocks — original 7 + constitutional blocks.
#[derive(Debug, Clone)]
pub enum BlockNode {
    // Original blocks
    Identity(IdentityNode),
    Interface(InterfaceNode),
    State(StateNode),
    Governance(GovernanceNode),
    Budget(BudgetNode),
    Memory(MemoryNode),
    Behavior(BehaviorNode),
    // Constitutional blocks (per CLS_CONSTITUTIONAL_LOGIC_ARCHITECTURE.md)
    Solution(SolutionNode),
    Imports(ImportsNode),
    Capabilities(CapabilitiesNode),
    Policy(PolicyNode),
    Flow(FlowNode),
    Evidence(EvidenceNode),
    Outcomes(OutcomesNode),
    Review(ReviewNode),
    Output(OutputBlockNode),
}

// ── Identity ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IdentityNode {
    pub entries: Vec<(String, String)>,
    pub span: Span,
}

// ── Interface ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InterfaceNode {
    pub inputs: Vec<InputDeclNode>,
    pub outputs: Vec<OutputDeclNode>,
    pub events: Vec<String>,
    pub tools: Vec<String>,
    pub capabilities: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct InputDeclNode {
    pub name: String,
    pub type_ann: TypeNode,
    pub required: bool,
    pub description: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct OutputDeclNode {
    pub name: String,
    pub type_ann: TypeNode,
    pub description: Option<String>,
    pub span: Span,
}

// ── Types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum TypeNode {
    Primitive(PrimitiveType),
    List(Box<TypeNode>),
    Map(Box<TypeNode>, Box<TypeNode>),
    // Extended types
    Optional(Box<TypeNode>),                    // T? — nullable type
    Enum(Vec<String>),                          // enum { A, B, C }
    Record(String),                             // record<T> — named record type
    // Domain types
    ToolResult(Box<TypeNode>),                  // tool_result<T>
    EvidenceRef,                                // evidence_ref — CID reference to evidence
    PolicyResult,                               // policy_result — allow/deny/hold
    // Trust wrappers
    Trusted(Box<TypeNode>),                     // trusted<T> — validated/signed
    Untrusted(Box<TypeNode>),                   // untrusted<T> — raw input
    Pii(Box<TypeNode>),                         // pii<T> — PII-labeled type
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrimitiveType {
    String,
    Text,       // Extended: multi-line text
    Int,
    Float,
    Bool,
    Json,
    Binary,
    Cid,
    // Domain primitives
    Date,
    Time,
    DateTime,
    Document,   // Document reference
    Reference,  // Generic reference
}

// ── State ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StateNode {
    pub states: Vec<StateDefNode>,
    pub transitions: Vec<TransitionDefNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct StateDefNode {
    pub name: String,
    pub kind: StateKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateKind {
    Initial,
    Terminal,
    Normal,
}

#[derive(Debug, Clone)]
pub struct TransitionDefNode {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub guard: Option<PredicateNode>,
    pub span: Span,
}

// ── Governance ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GovernanceNode {
    pub requires: Vec<PredicateNode>,
    pub ensures: Vec<PredicateNode>,
    pub invariants: Vec<PredicateNode>,
    pub roles: Vec<String>,
    pub clearance: Option<String>,
    pub compliance: Vec<String>,
    pub on_failure: Option<String>,
    pub span: Span,
}

// ── Predicates (recursive) ──────────────────────────────────────

#[derive(Debug, Clone)]
pub enum PredicateNode {
    IsPresent { field: String, span: Span },
    Compare { field: String, op: CmpOp, value: ExprNode, span: Span },
    InList { field: String, values: Vec<ExprNode>, span: Span },
    Matches { field: String, pattern: String, span: Span },
    HasRole { role: String, span: Span },
    BudgetCheck { resource: String, op: CmpOp, value: ExprNode, span: Span },
    And { left: Box<PredicateNode>, right: Box<PredicateNode>, span: Span },
    Or { left: Box<PredicateNode>, right: Box<PredicateNode>, span: Span },
    Not { inner: Box<PredicateNode>, span: Span },
}

impl PredicateNode {
    pub fn span(&self) -> Span {
        match self {
            PredicateNode::IsPresent { span, .. } => *span,
            PredicateNode::Compare { span, .. } => *span,
            PredicateNode::InList { span, .. } => *span,
            PredicateNode::Matches { span, .. } => *span,
            PredicateNode::HasRole { span, .. } => *span,
            PredicateNode::BudgetCheck { span, .. } => *span,
            PredicateNode::And { span, .. } => *span,
            PredicateNode::Or { span, .. } => *span,
            PredicateNode::Not { span, .. } => *span,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CmpOp {
    Gt,
    Lt,
    Gte,
    Lte,
    Eq,
    Neq,
}

// ── Budget ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BudgetNode {
    pub entries: Vec<BudgetEntryNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct BudgetEntryNode {
    pub resource: String,
    pub limit: ExprNode,
    pub span: Span,
}

// ── Memory ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemoryNode {
    pub uses: Vec<MemoryUseNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct MemoryUseNode {
    pub namespace: String,
    pub alias: String,
    pub span: Span,
}

// ── Behavior ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehaviorNode {
    pub steps: Vec<StepNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct StepNode {
    pub id: String,
    pub label: Option<String>,
    pub ops: Vec<StepOpNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum StepOpNode {
    ToolCall {
        tool_name: String,
        params: Vec<ParamNode>,
        bind: Option<String>,
        span: Span,
    },
    LlmInfer {
        prompt: String,
        with_vars: Vec<String>,
        max_tokens: Option<i64>,
        temperature: Option<f64>,
        bind: Option<String>,
        span: Span,
    },
    MemRecall {
        namespace: String,
        query: ExprNode,
        limit: Option<i64>,
        bind: Option<String>,
        span: Span,
    },
    MemRemember {
        namespace: String,
        content: ExprNode,
        tags: Vec<String>,
        span: Span,
    },
    SetVar {
        name: String,
        value: ExprNode,
        span: Span,
    },
    Branch {
        arms: Vec<BranchArmNode>,
        span: Span,
    },
    Transition {
        state: String,
        span: Span,
    },
    EmitEvent {
        event: String,
        data: Vec<ParamNode>,
        span: Span,
    },
    Checkpoint {
        label: String,
        span: Span,
    },
    CallContract {
        contract: String,
        params: Vec<ParamNode>,
        bind: Option<String>,
        span: Span,
    },
    SendMessage {
        target: String,
        payload: Vec<ParamNode>,
        span: Span,
    },
    WaitEvent {
        event: String,
        timeout: Option<i64>,
        span: Span,
    },
    Parallel {
        ops: Vec<StepOpNode>,
        span: Span,
    },
    Saga {
        forward: Box<StepOpNode>,
        compensate: Box<StepOpNode>,
        span: Span,
    },
}

// ═══════════════════════════════════════════════════════════════
// Constitutional AST Nodes (per CLS_CONSTITUTIONAL_LOGIC_ARCHITECTURE.md)
// ═══════════════════════════════════════════════════════════════

// ── Solution Block ──────────────────────────────────────────────
// solution claims_review version "1.0.0" { domain healthcare, owner "claims-team" }

#[derive(Debug, Clone)]
pub struct SolutionNode {
    pub name: String,
    pub version: Option<String>,
    pub domain: Option<String>,
    pub owner: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub span: Span,
}

// ── Imports Block ───────────────────────────────────────────────
// import schema PatientRecord
// import policy_pack hipaa_baseline
// import tool_contract payer_policy_check

#[derive(Debug, Clone)]
pub struct ImportsNode {
    pub imports: Vec<ImportDeclNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ImportDeclNode {
    pub kind: ImportKind,
    pub name: String,
    pub alias: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImportKind {
    Schema,
    PolicyPack,
    ToolContract,
}

// ── Capabilities Block ──────────────────────────────────────────
// tool icd10_lookup advisory
// memory payer_guidelines readonly
// protocol native
// model decision_model
// review_queue claims_manual_review

#[derive(Debug, Clone)]
pub struct CapabilitiesNode {
    pub capabilities: Vec<CapabilityDeclNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CapabilityDeclNode {
    pub kind: CapabilityKind,
    pub name: String,
    pub modifier: Option<CapabilityModifier>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityKind {
    Tool,
    Memory,
    Protocol,
    Model,
    ReviewQueue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityModifier {
    Advisory,
    Binding,
    Readonly,
    Readwrite,
}

// ── Policy Block ────────────────────────────────────────────────
// require audit_trail
// require human_review when confidence < 0.80
// deny export_pii outside case_context
// deny tool external_web_search unless approved
// require output conforms claims_decision_schema

#[derive(Debug, Clone)]
pub struct PolicyNode {
    pub rules: Vec<PolicyRuleNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct PolicyRuleNode {
    pub kind: PolicyRuleKind,
    pub subject: String,
    pub condition: Option<PredicateNode>,
    pub modifier: Option<PolicyModifier>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyRuleKind {
    Require,
    Deny,
    Allow,
}

#[derive(Debug, Clone)]
pub struct PolicyModifier {
    pub kind: PolicyModifierKind,
    pub target: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyModifierKind {
    Outside,
    Unless,
    Conforms,
}

// ── Flow Block with Stages ──────────────────────────────────────
// flow { stage validate { ... } stage analyze { ... } }

#[derive(Debug, Clone)]
pub struct FlowNode {
    pub stages: Vec<StageNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct StageNode {
    pub name: String,
    pub ops: Vec<StageOpNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum StageOpNode {
    Require { predicate: PredicateNode, span: Span },
    Call { tool: String, params: Vec<ParamNode>, bind: Option<String>, span: Span },
    Emit { output: String, data: Vec<ParamNode>, span: Span },
    Route { target: String, outcome: Option<String>, span: Span },
    Fail { message: String, outcome: Option<String>, span: Span },
    When { predicate: PredicateNode, body: Vec<StageOpNode>, otherwise: Option<Vec<StageOpNode>>, span: Span },
    Bind { name: String, value: ExprNode, span: Span },
}

// ── Evidence Block ──────────────────────────────────────────────
// record input_hash
// record tool_calls
// verify chain_integrity

#[derive(Debug, Clone)]
pub struct EvidenceNode {
    pub entries: Vec<EvidenceEntryNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EvidenceEntryNode {
    pub kind: EvidenceKind,
    pub subject: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceKind {
    Record,
    Verify,
}

// ── Outcomes Block ──────────────────────────────────────────────
// outcomes { approve, reject, escalate, blocked }

#[derive(Debug, Clone)]
pub struct OutcomesNode {
    pub outcomes: Vec<String>,
    pub span: Span,
}

// ── Review Block ────────────────────────────────────────────────
// review human_review { required when confidence < 0.80, queue claims_manual_review, on_timeout route to blocked }

#[derive(Debug, Clone)]
pub struct ReviewNode {
    pub name: String,
    pub required_when: Option<PredicateNode>,
    pub queue: Option<String>,
    pub on_timeout: Option<ReviewTimeoutAction>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ReviewTimeoutAction {
    pub action: String,
    pub target: String,
    pub span: Span,
}

// ── Output Block ────────────────────────────────────────────────
// output {
//     decision: enum { approve, reject, escalate } required
//     confidence: float range 0.0..1.0
//     reasoning: text required evidence_ref
//     supporting_docs: List<document> min_items 1
// }

#[derive(Debug, Clone)]
pub struct OutputBlockNode {
    pub fields: Vec<OutputFieldNode>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct OutputFieldNode {
    pub name: String,
    pub type_ann: TypeNode,
    pub required: bool,
    pub constraints: Vec<ValidationConstraint>,
    pub evidence_ref: bool,
    pub description: Option<String>,
    pub span: Span,
}

/// Validation constraints for output fields
#[derive(Debug, Clone)]
pub enum ValidationConstraint {
    /// Range constraint: range min..max
    Range { min: Option<ExprNode>, max: Option<ExprNode> },
    /// Minimum items for lists: min_items N
    MinItems(i64),
    /// Maximum items for lists: max_items N
    MaxItems(i64),
    /// Pattern constraint: pattern "regex"
    Pattern(String),
    /// Minimum length for strings: min_length N
    MinLength(i64),
    /// Maximum length for strings: max_length N
    MaxLength(i64),
    /// One of constraint: one_of [a, b, c]
    OneOf(Vec<ExprNode>),
}

// ═══════════════════════════════════════════════════════════════
// Supporting nodes
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ParamNode {
    pub key: String,
    pub value: ExprNode,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct BranchArmNode {
    pub predicate: Option<PredicateNode>,
    pub target: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum ExprNode {
    StringLit(String, Span),
    IntLit(i64, Span),
    FloatLit(f64, Span),
    BoolLit(bool, Span),
    NullLit(Span),
    VarRef(String, Span),
    Ident(String, Span),
    ObjectLit(Vec<ParamNode>, Span),
    ListLit(Vec<ExprNode>, Span),
}

impl ExprNode {
    pub fn span(&self) -> Span {
        match self {
            ExprNode::StringLit(_, s) => *s,
            ExprNode::IntLit(_, s) => *s,
            ExprNode::FloatLit(_, s) => *s,
            ExprNode::BoolLit(_, s) => *s,
            ExprNode::NullLit(s) => *s,
            ExprNode::VarRef(_, s) => *s,
            ExprNode::Ident(_, s) => *s,
            ExprNode::ObjectLit(_, s) => *s,
            ExprNode::ListLit(_, s) => *s,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Parse Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ParseError {
    pub span: Span,
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Parser
// ═══════════════════════════════════════════════════════════════

pub struct CclParser {
    tokens: Vec<Token>,
    pos: usize,
    errors: Vec<ParseError>,
}

impl CclParser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0, errors: Vec::new() }
    }

    /// Parse source string into AST.
    pub fn parse(source: &str) -> Result<ContractNode, Vec<ParseError>> {
        let tokens = CclLexer::tokenize_filtered(source);
        let mut parser = CclParser::new(tokens);
        let contract = parser.parse_contract();
        if parser.errors.is_empty() {
            Ok(contract)
        } else {
            Err(parser.errors)
        }
    }

    pub fn errors(&self) -> &[ParseError] {
        &self.errors
    }

    // ── Cursor helpers ──────────────────────────────────────────

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or_else(|| self.tokens.last().unwrap())
    }

    fn peek_kind(&self) -> &TokenKind {
        &self.peek().kind
    }

    fn at(&self, kind: &TokenKind) -> bool {
        std::mem::discriminant(&self.peek().kind) == std::mem::discriminant(kind)
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek_kind(), TokenKind::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.peek().clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, kind: &TokenKind) -> Result<Token, ()> {
        if self.at(kind) {
            Ok(self.advance())
        } else {
            self.error_at_current(
                "E_UNEXPECTED",
                format!("expected {:?}, found {:?}", kind, self.peek_kind()),
            );
            Err(())
        }
    }

    fn expect_ident(&mut self) -> Result<String, ()> {
        // Delegate to expect_ident_or_keyword to allow keywords as identifiers
        self.expect_ident_or_keyword()
    }

    /// Accept an identifier OR a keyword that can be used as a field/contract name.
    /// This handles cases like `version:` in identity blocks where `version` is also a keyword,
    /// or `flow` as a contract name where `flow` is also a block keyword.
    fn expect_ident_or_keyword(&mut self) -> Result<String, ()> {
        match self.peek_kind().clone() {
            TokenKind::Ident(name) => { self.advance(); Ok(name) }
            // Keywords that can also be used as identifiers in certain contexts
            TokenKind::KwVersion => { self.advance(); Ok("version".into()) }
            TokenKind::KwDomain => { self.advance(); Ok("domain".into()) }
            TokenKind::KwOwner => { self.advance(); Ok("owner".into()) }
            TokenKind::KwSchema => { self.advance(); Ok("schema".into()) }
            TokenKind::KwQueue => { self.advance(); Ok("queue".into()) }
            TokenKind::KwModel => { self.advance(); Ok("model".into()) }
            TokenKind::KwProtocol => { self.advance(); Ok("protocol".into()) }
            TokenKind::KwRequired => { self.advance(); Ok("required".into()) }
            TokenKind::KwInput => { self.advance(); Ok("input".into()) }
            TokenKind::KwOutput => { self.advance(); Ok("output".into()) }
            TokenKind::KwState => { self.advance(); Ok("state".into()) }
            TokenKind::KwTool => { self.advance(); Ok("tool".into()) }
            TokenKind::KwMemory => { self.advance(); Ok("memory".into()) }
            // Constitutional block keywords that can also be identifiers
            TokenKind::KwFlow => { self.advance(); Ok("flow".into()) }
            TokenKind::KwEvidence => { self.advance(); Ok("evidence".into()) }
            TokenKind::KwOutcomes => { self.advance(); Ok("outcomes".into()) }
            TokenKind::KwReview => { self.advance(); Ok("review".into()) }
            TokenKind::KwSolution => { self.advance(); Ok("solution".into()) }
            TokenKind::KwCapabilities => { self.advance(); Ok("capabilities".into()) }
            TokenKind::KwPolicy => { self.advance(); Ok("policy".into()) }
            TokenKind::KwStage => { self.advance(); Ok("stage".into()) }
            TokenKind::KwRecord => { self.advance(); Ok("record".into()) }
            TokenKind::KwVerify => { self.advance(); Ok("verify".into()) }
            TokenKind::KwRoute => { self.advance(); Ok("route".into()) }
            TokenKind::KwFail => { self.advance(); Ok("fail".into()) }
            TokenKind::KwAllow => { self.advance(); Ok("allow".into()) }
            TokenKind::KwDeny => { self.advance(); Ok("deny".into()) }
            TokenKind::KwOutside => { self.advance(); Ok("outside".into()) }
            TokenKind::KwUnless => { self.advance(); Ok("unless".into()) }
            TokenKind::KwConforms => { self.advance(); Ok("conforms".into()) }
            TokenKind::KwAdvisory => { self.advance(); Ok("advisory".into()) }
            TokenKind::KwBinding => { self.advance(); Ok("binding".into()) }
            TokenKind::KwReadonly => { self.advance(); Ok("readonly".into()) }
            TokenKind::KwReadwrite => { self.advance(); Ok("readwrite".into()) }
            // Extended type keywords that can also be identifiers
            TokenKind::KwText => { self.advance(); Ok("text".into()) }
            TokenKind::KwEnum => { self.advance(); Ok("enum".into()) }
            TokenKind::KwDate => { self.advance(); Ok("date".into()) }
            TokenKind::KwTime => { self.advance(); Ok("time".into()) }
            TokenKind::KwDateTime => { self.advance(); Ok("datetime".into()) }
            TokenKind::KwDocument => { self.advance(); Ok("document".into()) }
            TokenKind::KwReference => { self.advance(); Ok("reference".into()) }
            TokenKind::KwToolResult => { self.advance(); Ok("tool_result".into()) }
            TokenKind::KwEvidenceRef => { self.advance(); Ok("evidence_ref".into()) }
            TokenKind::KwPolicyResult => { self.advance(); Ok("policy_result".into()) }
            TokenKind::KwTrusted => { self.advance(); Ok("trusted".into()) }
            TokenKind::KwPii => { self.advance(); Ok("pii".into()) }
            // Validation constraint keywords
            TokenKind::KwRange => { self.advance(); Ok("range".into()) }
            TokenKind::KwMinItems => { self.advance(); Ok("min_items".into()) }
            TokenKind::KwMaxItems => { self.advance(); Ok("max_items".into()) }
            TokenKind::KwMinLength => { self.advance(); Ok("min_length".into()) }
            TokenKind::KwMaxLength => { self.advance(); Ok("max_length".into()) }
            TokenKind::KwPattern => { self.advance(); Ok("pattern".into()) }
            TokenKind::KwOneOf => { self.advance(); Ok("one_of".into()) }
            _ => {
                self.error_at_current("E_EXPECTED_IDENT", format!("expected identifier, found {:?}", self.peek_kind()));
                Err(())
            }
        }
    }

    fn expect_string(&mut self) -> Result<String, ()> {
        if let TokenKind::StringLit(s) = self.peek_kind().clone() {
            self.advance();
            Ok(s)
        } else {
            self.error_at_current("E_EXPECTED_STRING", format!("expected string literal, found {:?}", self.peek_kind()));
            Err(())
        }
    }

    fn try_consume(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn error_at_current(&mut self, code: &str, message: String) {
        self.errors.push(ParseError {
            span: self.peek().span,
            code: code.to_string(),
            message,
            hint: None,
        });
    }

    /// Synchronize: skip tokens until we find one of the block keywords or EOF.
    fn synchronize_block(&mut self) {
        while !self.at_eof() {
            match self.peek_kind() {
                // Original blocks
                TokenKind::KwIdentity | TokenKind::KwInterface | TokenKind::KwState |
                TokenKind::KwGovernance | TokenKind::KwBudget | TokenKind::KwMemory |
                TokenKind::KwBehavior |
                // Constitutional blocks
                TokenKind::KwSolution | TokenKind::KwImport | TokenKind::KwCapabilities |
                TokenKind::KwPolicy | TokenKind::KwFlow | TokenKind::KwEvidence |
                TokenKind::KwOutcomes | TokenKind::KwReview |
                TokenKind::RBrace => return,
                _ => { self.advance(); }
            }
        }
    }

    /// Synchronize at step level.
    fn synchronize_step(&mut self) {
        while !self.at_eof() {
            match self.peek_kind() {
                TokenKind::KwStep | TokenKind::RBrace => return,
                _ => { self.advance(); }
            }
        }
    }

    // ── Top-level parsing ───────────────────────────────────────

    fn parse_contract(&mut self) -> ContractNode {
        let start = self.peek().span.start;
        // contract <name> { ... }
        let _ = self.expect(&TokenKind::KwContract);
        // Use expect_ident_or_keyword to allow keywords like 'flow' as contract names
        let name = self.expect_ident_or_keyword().unwrap_or_else(|_| "unnamed".into());
        let _ = self.expect(&TokenKind::LBrace);

        let mut blocks = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.peek_kind().clone() {
                TokenKind::KwIdentity => {
                    if let Some(b) = self.parse_identity_block() {
                        blocks.push(BlockNode::Identity(b));
                    }
                }
                TokenKind::KwInterface => {
                    if let Some(b) = self.parse_interface_block() {
                        blocks.push(BlockNode::Interface(b));
                    }
                }
                TokenKind::KwState => {
                    if let Some(b) = self.parse_state_block() {
                        blocks.push(BlockNode::State(b));
                    }
                }
                TokenKind::KwGovernance => {
                    if let Some(b) = self.parse_governance_block() {
                        blocks.push(BlockNode::Governance(b));
                    }
                }
                TokenKind::KwBudget => {
                    if let Some(b) = self.parse_budget_block() {
                        blocks.push(BlockNode::Budget(b));
                    }
                }
                TokenKind::KwMemory => {
                    if let Some(b) = self.parse_memory_block() {
                        blocks.push(BlockNode::Memory(b));
                    }
                }
                TokenKind::KwBehavior => {
                    if let Some(b) = self.parse_behavior_block() {
                        blocks.push(BlockNode::Behavior(b));
                    }
                }
                // Constitutional blocks
                TokenKind::KwSolution => {
                    if let Some(b) = self.parse_solution_block() {
                        blocks.push(BlockNode::Solution(b));
                    }
                }
                TokenKind::KwImport => {
                    // Collect imports into a single ImportsNode
                    let mut imports = Vec::new();
                    while self.at(&TokenKind::KwImport) {
                        if let Some(imp) = self.parse_import_decl() {
                            imports.push(imp);
                        } else {
                            // Failed to parse import, advance to avoid infinite loop
                            self.advance();
                            break;
                        }
                    }
                    if !imports.is_empty() {
                        let span = Span::new(imports.first().unwrap().span.start, imports.last().unwrap().span.end);
                        blocks.push(BlockNode::Imports(ImportsNode { imports, span }));
                    }
                }
                TokenKind::KwCapabilities => {
                    if let Some(b) = self.parse_capabilities_block() {
                        blocks.push(BlockNode::Capabilities(b));
                    }
                }
                TokenKind::KwPolicy => {
                    if let Some(b) = self.parse_policy_block() {
                        blocks.push(BlockNode::Policy(b));
                    }
                }
                TokenKind::KwFlow => {
                    if let Some(b) = self.parse_flow_block() {
                        blocks.push(BlockNode::Flow(b));
                    }
                }
                TokenKind::KwEvidence => {
                    if let Some(b) = self.parse_evidence_block() {
                        blocks.push(BlockNode::Evidence(b));
                    }
                }
                TokenKind::KwOutcomes => {
                    if let Some(b) = self.parse_outcomes_block() {
                        blocks.push(BlockNode::Outcomes(b));
                    }
                }
                TokenKind::KwReview => {
                    if let Some(b) = self.parse_review_block() {
                        blocks.push(BlockNode::Review(b));
                    }
                }
                TokenKind::KwOutput => {
                    if let Some(b) = self.parse_output_block() {
                        blocks.push(BlockNode::Output(b));
                    }
                }
                _ => {
                    self.error_at_current("E_BAD_BLOCK", format!("expected block keyword, found {:?}", self.peek_kind()));
                    self.synchronize_block();
                }
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        let end = self.peek().span.end;
        ContractNode { name, blocks, span: Span::new(start, end) }
    }

    // ── Identity block ──────────────────────────────────────────

    fn parse_identity_block(&mut self) -> Option<IdentityNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'identity'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }

        let mut entries = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            // Use expect_ident_or_keyword to handle keywords like 'version' as field names
            if let Ok(key) = self.expect_ident_or_keyword() {
                let _ = self.expect(&TokenKind::Colon);
                if let Ok(value) = self.expect_string() {
                    entries.push((key, value));
                }
            } else {
                self.synchronize_block();
                break;
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(IdentityNode { entries, span: Span::new(start, self.peek().span.end) })
    }

    // ── Interface block ─────────────────────────────────────────

    fn parse_interface_block(&mut self) -> Option<InterfaceNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'interface'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }

        let mut node = InterfaceNode {
            inputs: vec![], outputs: vec![], events: vec![], tools: vec![], capabilities: vec![],
            span: Span::default(),
        };

        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.peek_kind().clone() {
                TokenKind::KwInput => {
                    self.advance();
                    if let Some(inp) = self.parse_input_decl() {
                        node.inputs.push(inp);
                    }
                }
                TokenKind::KwOutput => {
                    self.advance();
                    if let Some(out) = self.parse_output_decl() {
                        node.outputs.push(out);
                    }
                }
                TokenKind::KwEvent => {
                    self.advance();
                    if let Ok(name) = self.expect_ident() {
                        node.events.push(name);
                    }
                }
                TokenKind::KwTool => {
                    self.advance();
                    if let Ok(name) = self.expect_ident() {
                        node.tools.push(name);
                    }
                }
                TokenKind::KwCapability => {
                    self.advance();
                    if let Ok(name) = self.expect_ident() {
                        node.capabilities.push(name);
                    }
                }
                _ => {
                    self.error_at_current("E_BAD_INTERFACE", format!("expected input/output/event/tool/capability, found {:?}", self.peek_kind()));
                    self.advance();
                }
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        node.span = Span::new(start, self.peek().span.end);
        Some(node)
    }

    fn parse_input_decl(&mut self) -> Option<InputDeclNode> {
        let start = self.peek().span.start;
        let name = self.expect_ident().ok()?;
        let _ = self.expect(&TokenKind::Colon);
        let type_ann = self.parse_type()?;
        let required = self.try_consume(&TokenKind::KwRequired);
        let _optional = if !required { self.try_consume(&TokenKind::KwOptional) } else { false };
        let description = if let TokenKind::StringLit(_) = self.peek_kind() {
            Some(self.expect_string().ok()?)
        } else { None };
        Some(InputDeclNode { name, type_ann, required, description, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_output_decl(&mut self) -> Option<OutputDeclNode> {
        let start = self.peek().span.start;
        let name = self.expect_ident().ok()?;
        let _ = self.expect(&TokenKind::Colon);
        let type_ann = self.parse_type()?;
        let description = if let TokenKind::StringLit(_) = self.peek_kind() {
            Some(self.expect_string().ok()?)
        } else { None };
        Some(OutputDeclNode { name, type_ann, description, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_type(&mut self) -> Option<TypeNode> {
        let base_type = self.parse_base_type()?;
        
        // Check for optional modifier: T?
        if self.at(&TokenKind::Question) {
            self.advance();
            Some(TypeNode::Optional(Box::new(base_type)))
        } else {
            Some(base_type)
        }
    }
    
    fn parse_base_type(&mut self) -> Option<TypeNode> {
        match self.peek_kind().clone() {
            // Basic primitives
            TokenKind::KwString => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::String)) }
            TokenKind::KwInt => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Int)) }
            TokenKind::KwFloat => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Float)) }
            TokenKind::KwBool => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Bool)) }
            TokenKind::KwJson => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Json)) }
            TokenKind::KwBinary => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Binary)) }
            TokenKind::KwCid => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Cid)) }
            // Extended primitives
            TokenKind::KwText => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Text)) }
            TokenKind::KwDate => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Date)) }
            TokenKind::KwTime => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Time)) }
            TokenKind::KwDateTime => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::DateTime)) }
            TokenKind::KwDocument => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Document)) }
            TokenKind::KwReference => { self.advance(); Some(TypeNode::Primitive(PrimitiveType::Reference)) }
            // Domain types
            TokenKind::KwEvidenceRef => { self.advance(); Some(TypeNode::EvidenceRef) }
            TokenKind::KwPolicyResult => { self.advance(); Some(TypeNode::PolicyResult) }
            // Container types
            TokenKind::KwList => {
                self.advance();
                let _ = self.expect(&TokenKind::Lt);
                let inner = self.parse_type()?;
                let _ = self.expect(&TokenKind::Gt);
                Some(TypeNode::List(Box::new(inner)))
            }
            TokenKind::KwMap => {
                self.advance();
                let _ = self.expect(&TokenKind::Lt);
                let key = self.parse_type()?;
                let _ = self.expect(&TokenKind::Comma);
                let val = self.parse_type()?;
                let _ = self.expect(&TokenKind::Gt);
                Some(TypeNode::Map(Box::new(key), Box::new(val)))
            }
            // Parameterized types
            TokenKind::KwToolResult => {
                self.advance();
                let _ = self.expect(&TokenKind::Lt);
                let inner = self.parse_type()?;
                let _ = self.expect(&TokenKind::Gt);
                Some(TypeNode::ToolResult(Box::new(inner)))
            }
            TokenKind::KwTrusted => {
                self.advance();
                let _ = self.expect(&TokenKind::Lt);
                let inner = self.parse_type()?;
                let _ = self.expect(&TokenKind::Gt);
                Some(TypeNode::Trusted(Box::new(inner)))
            }
            TokenKind::KwUntrusted => {
                self.advance();
                let _ = self.expect(&TokenKind::Lt);
                let inner = self.parse_type()?;
                let _ = self.expect(&TokenKind::Gt);
                Some(TypeNode::Untrusted(Box::new(inner)))
            }
            TokenKind::KwPii => {
                self.advance();
                let _ = self.expect(&TokenKind::Lt);
                let inner = self.parse_type()?;
                let _ = self.expect(&TokenKind::Gt);
                Some(TypeNode::Pii(Box::new(inner)))
            }
            // Record type: record<TypeName>
            TokenKind::KwRecord => {
                self.advance();
                let _ = self.expect(&TokenKind::Lt);
                let name = self.expect_ident().ok()?;
                let _ = self.expect(&TokenKind::Gt);
                Some(TypeNode::Record(name))
            }
            // Enum type: enum { A, B, C }
            TokenKind::KwEnum => {
                self.advance();
                let _ = self.expect(&TokenKind::LBrace);
                let mut variants = Vec::new();
                while !self.at(&TokenKind::RBrace) && !self.at_eof() {
                    if let Ok(name) = self.expect_ident() {
                        variants.push(name);
                    }
                    if !self.try_consume(&TokenKind::Comma) {
                        break;
                    }
                }
                let _ = self.expect(&TokenKind::RBrace);
                Some(TypeNode::Enum(variants))
            }
            _ => {
                self.error_at_current("E_BAD_TYPE", format!("expected type, found {:?}", self.peek_kind()));
                None
            }
        }
    }

    // ── State block ─────────────────────────────────────────────

    fn parse_state_block(&mut self) -> Option<StateNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'state'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }

        let mut states = Vec::new();
        let mut transitions = Vec::new();

        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.peek_kind().clone() {
                TokenKind::KwInitial => {
                    let s = self.peek().span.start;
                    self.advance();
                    if let Ok(name) = self.expect_ident() {
                        states.push(StateDefNode { name, kind: StateKind::Initial, span: Span::new(s, self.peek().span.end) });
                    }
                }
                TokenKind::KwTerminal => {
                    let s = self.peek().span.start;
                    self.advance();
                    if let Ok(name) = self.expect_ident() {
                        states.push(StateDefNode { name, kind: StateKind::Terminal, span: Span::new(s, self.peek().span.end) });
                    }
                }
                TokenKind::Ident(_) => {
                    // Could be state name or transition: from -> to on trigger
                    let s = self.peek().span.start;
                    let name = self.expect_ident().ok()?;
                    if self.at(&TokenKind::Arrow) {
                        // transition: from -> to on trigger [when guard]
                        self.advance(); // consume ->
                        let to = self.expect_ident().ok()?;
                        let trigger = if self.try_consume(&TokenKind::KwOn) {
                            self.expect_ident().unwrap_or_else(|_| "unknown".into())
                        } else { "auto".into() };
                        let guard = if self.at(&TokenKind::KwWhen) {
                            self.advance();
                            self.parse_predicate().ok()
                        } else { None };
                        transitions.push(TransitionDefNode {
                            from: name, to, trigger, guard,
                            span: Span::new(s, self.peek().span.end),
                        });
                    } else {
                        // plain state declaration
                        states.push(StateDefNode { name, kind: StateKind::Normal, span: Span::new(s, self.peek().span.end) });
                    }
                }
                _ => {
                    self.error_at_current("E_BAD_STATE", format!("expected state definition, found {:?}", self.peek_kind()));
                    self.advance();
                }
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(StateNode { states, transitions, span: Span::new(start, self.peek().span.end) })
    }

    // ── Governance block ────────────────────────────────────────

    fn parse_governance_block(&mut self) -> Option<GovernanceNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'governance'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }

        let mut node = GovernanceNode {
            requires: vec![], ensures: vec![], invariants: vec![],
            roles: vec![], clearance: None, compliance: vec![], on_failure: None,
            span: Span::default(),
        };

        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.peek_kind().clone() {
                TokenKind::KwRequire => {
                    self.advance();
                    if let Ok(pred) = self.parse_predicate() {
                        node.requires.push(pred);
                    }
                }
                TokenKind::KwEnsure => {
                    self.advance();
                    if let Ok(pred) = self.parse_predicate() {
                        node.ensures.push(pred);
                    }
                }
                TokenKind::KwInvariant => {
                    self.advance();
                    if let Ok(pred) = self.parse_predicate() {
                        node.invariants.push(pred);
                    }
                }
                TokenKind::KwRoles => {
                    self.advance();
                    if self.try_consume(&TokenKind::LBracket) {
                        while !self.at(&TokenKind::RBracket) && !self.at_eof() {
                            if let Ok(r) = self.expect_ident() {
                                node.roles.push(r);
                            }
                            self.try_consume(&TokenKind::Comma);
                        }
                        self.try_consume(&TokenKind::RBracket);
                    }
                }
                TokenKind::KwClearance => {
                    self.advance();
                    node.clearance = self.expect_string().ok().or_else(|| self.expect_ident().ok());
                }
                TokenKind::KwCompliance => {
                    self.advance();
                    if self.try_consume(&TokenKind::LBracket) {
                        while !self.at(&TokenKind::RBracket) && !self.at_eof() {
                            if let Ok(c) = self.expect_ident() {
                                node.compliance.push(c);
                            }
                            self.try_consume(&TokenKind::Comma);
                        }
                        self.try_consume(&TokenKind::RBracket);
                    }
                }
                TokenKind::KwOnFailure => {
                    self.advance();
                    node.on_failure = self.expect_ident().ok();
                }
                _ => {
                    self.error_at_current("E_BAD_GOVERNANCE", format!("expected governance entry, found {:?}", self.peek_kind()));
                    self.advance();
                }
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        node.span = Span::new(start, self.peek().span.end);
        Some(node)
    }

    // ── Predicate parsing (precedence climbing) ─────────────────

    fn parse_predicate(&mut self) -> Result<PredicateNode, ()> {
        self.parse_or_predicate()
    }

    fn parse_or_predicate(&mut self) -> Result<PredicateNode, ()> {
        let mut left = self.parse_and_predicate()?;
        while self.at(&TokenKind::KwOr) {
            let start = left.span().start;
            self.advance();
            let right = self.parse_and_predicate()?;
            let end = right.span().end;
            left = PredicateNode::Or { left: Box::new(left), right: Box::new(right), span: Span::new(start, end) };
        }
        Ok(left)
    }

    fn parse_and_predicate(&mut self) -> Result<PredicateNode, ()> {
        let mut left = self.parse_unary_predicate()?;
        while self.at(&TokenKind::KwAnd) {
            let start = left.span().start;
            self.advance();
            let right = self.parse_unary_predicate()?;
            let end = right.span().end;
            left = PredicateNode::And { left: Box::new(left), right: Box::new(right), span: Span::new(start, end) };
        }
        Ok(left)
    }

    fn parse_unary_predicate(&mut self) -> Result<PredicateNode, ()> {
        if self.at(&TokenKind::KwNot) {
            let start = self.peek().span.start;
            self.advance();
            let inner = self.parse_unary_predicate()?;
            let end = inner.span().end;
            return Ok(PredicateNode::Not { inner: Box::new(inner), span: Span::new(start, end) });
        }
        self.parse_primary_predicate()
    }

    fn parse_primary_predicate(&mut self) -> Result<PredicateNode, ()> {
        if self.at(&TokenKind::LParen) {
            self.advance();
            let pred = self.parse_predicate()?;
            let _ = self.expect(&TokenKind::RParen);
            return Ok(pred);
        }

        // agent has role <ident>
        if self.at(&TokenKind::KwAgent) {
            let start = self.peek().span.start;
            self.advance();
            let _ = self.expect(&TokenKind::KwHas);
            let _ = self.expect(&TokenKind::KwRole);
            let role = self.expect_ident()?;
            return Ok(PredicateNode::HasRole { role, span: Span::new(start, self.peek().span.end) });
        }

        // budget.resource op value — handle both Ident("budget") and KwBudget
        let is_budget = match self.peek_kind() {
            TokenKind::Ident(name) if name == "budget" => true,
            TokenKind::KwBudget => true,
            _ => false,
        };
        if is_budget {
            let start = self.peek().span.start;
            self.advance(); // consume 'budget' (keyword or ident)
            if self.at(&TokenKind::Dot) {
                let _ = self.expect(&TokenKind::Dot);
                let resource = self.expect_ident()?;
                let op = self.parse_cmp_op()?;
                let value = self.parse_expr()?;
                return Ok(PredicateNode::BudgetCheck { resource, op, value, span: Span::new(start, self.peek().span.end) });
            }
            // fallback: treat 'budget' as a field name for is_present etc.
            let field = "budget".to_string();
            if self.at(&TokenKind::KwIs) {
                self.advance();
                if self.try_consume(&TokenKind::KwPresent) {
                    return Ok(PredicateNode::IsPresent { field, span: Span::new(start, self.peek().span.end) });
                }
            }
            if let Ok(op) = self.parse_cmp_op() {
                let value = self.parse_expr()?;
                return Ok(PredicateNode::Compare { field, op, value, span: Span::new(start, self.peek().span.end) });
            }
            return Ok(PredicateNode::IsPresent { field, span: Span::new(start, self.peek().span.end) });
        }

        // field-based predicates: get field identifier or VarRef
        let start = self.peek().span.start;
        let field = match self.peek_kind().clone() {
            TokenKind::Ident(name) => { self.advance(); name }
            TokenKind::VarRef(path) => { self.advance(); path }
            _ => {
                self.error_at_current("E_BAD_PREDICATE", format!("expected predicate field, found {:?}", self.peek_kind()));
                return Err(());
            }
        };

        // field is present
        if self.at(&TokenKind::KwIs) {
            self.advance();
            if self.try_consume(&TokenKind::KwPresent) {
                return Ok(PredicateNode::IsPresent { field, span: Span::new(start, self.peek().span.end) });
            }
        }

        // field in [values]
        if self.at(&TokenKind::KwIn) {
            self.advance();
            let _ = self.expect(&TokenKind::LBracket);
            let mut values = Vec::new();
            while !self.at(&TokenKind::RBracket) && !self.at_eof() {
                values.push(self.parse_expr()?);
                self.try_consume(&TokenKind::Comma);
            }
            let _ = self.expect(&TokenKind::RBracket);
            return Ok(PredicateNode::InList { field, values, span: Span::new(start, self.peek().span.end) });
        }

        // field matches "pattern"
        if self.at(&TokenKind::KwMatches) {
            self.advance();
            let pattern = self.expect_string()?;
            return Ok(PredicateNode::Matches { field, pattern, span: Span::new(start, self.peek().span.end) });
        }

        // field op value (comparison)
        if let Ok(op) = self.parse_cmp_op() {
            let value = self.parse_expr()?;
            return Ok(PredicateNode::Compare { field, op, value, span: Span::new(start, self.peek().span.end) });
        }

        // Just a present check as fallback
        Ok(PredicateNode::IsPresent { field, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_cmp_op(&mut self) -> Result<CmpOp, ()> {
        match self.peek_kind() {
            TokenKind::Gt => { self.advance(); Ok(CmpOp::Gt) }
            TokenKind::Lt => { self.advance(); Ok(CmpOp::Lt) }
            TokenKind::Gte => { self.advance(); Ok(CmpOp::Gte) }
            TokenKind::Lte => { self.advance(); Ok(CmpOp::Lte) }
            TokenKind::Eq => { self.advance(); Ok(CmpOp::Eq) }
            TokenKind::Neq => { self.advance(); Ok(CmpOp::Neq) }
            _ => Err(())
        }
    }

    // ── Budget block ────────────────────────────────────────────

    fn parse_budget_block(&mut self) -> Option<BudgetNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'budget'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }

        let mut entries = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let s = self.peek().span.start;
            if let Ok(resource) = self.expect_ident() {
                let _ = self.expect(&TokenKind::Colon);
                if let Ok(limit) = self.parse_expr() {
                    entries.push(BudgetEntryNode { resource, limit, span: Span::new(s, self.peek().span.end) });
                }
            } else {
                self.advance();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(BudgetNode { entries, span: Span::new(start, self.peek().span.end) })
    }

    // ── Memory block ────────────────────────────────────────────

    fn parse_memory_block(&mut self) -> Option<MemoryNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'memory'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }

        let mut uses = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let s = self.peek().span.start;
            if self.try_consume(&TokenKind::KwUse) {
                if let Ok(namespace) = self.expect_ident() {
                    let alias = if self.try_consume(&TokenKind::KwAs) {
                        self.expect_ident().unwrap_or_else(|_| namespace.clone())
                    } else {
                        namespace.clone()
                    };
                    uses.push(MemoryUseNode { namespace, alias, span: Span::new(s, self.peek().span.end) });
                }
            } else {
                self.error_at_current("E_BAD_MEMORY", format!("expected 'use', found {:?}", self.peek_kind()));
                self.advance();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(MemoryNode { uses, span: Span::new(start, self.peek().span.end) })
    }

    // ── Behavior block ──────────────────────────────────────────

    fn parse_behavior_block(&mut self) -> Option<BehaviorNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'behavior'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }

        let mut steps = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            if self.at(&TokenKind::KwStep) {
                if let Some(step) = self.parse_step() {
                    steps.push(step);
                }
            } else {
                self.error_at_current("E_EXPECTED_STEP", format!("expected 'step', found {:?}", self.peek_kind()));
                self.synchronize_step();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(BehaviorNode { steps, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_step(&mut self) -> Option<StepNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'step'
        let id = self.expect_ident().ok()?;
        let label = if let TokenKind::StringLit(_) = self.peek_kind() {
            Some(self.expect_string().ok()?)
        } else { None };
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_step(); return None; }

        let mut ops = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            if let Some(op) = self.parse_step_op() {
                ops.push(op);
            } else {
                self.advance();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(StepNode { id, label, ops, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_step_op(&mut self) -> Option<StepOpNode> {
        let start = self.peek().span.start;
        match self.peek_kind().clone() {
            TokenKind::KwTool => self.parse_tool_call(start),
            TokenKind::KwInfer => self.parse_infer(start),
            TokenKind::KwRecall => self.parse_recall(start),
            TokenKind::KwRemember => self.parse_remember(start),
            TokenKind::KwSet => self.parse_set_var(start),
            TokenKind::KwBranch => self.parse_branch(start),
            TokenKind::KwTransition => self.parse_transition(start),
            TokenKind::KwEmit => self.parse_emit_event(start),
            TokenKind::KwCheckpoint => self.parse_checkpoint(start),
            TokenKind::KwCall => self.parse_call_contract(start),
            TokenKind::KwSend => self.parse_send_message(start),
            TokenKind::KwWait => self.parse_wait_event(start),
            TokenKind::KwParallel => self.parse_parallel(start),
            TokenKind::KwSaga => self.parse_saga(start),
            _ => {
                self.error_at_current("E_BAD_OP", format!("expected step operation, found {:?}", self.peek_kind()));
                None
            }
        }
    }

    // ── Step operations ─────────────────────────────────────────

    fn parse_tool_call(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'tool'
        let tool_name = self.expect_ident().ok()?;
        let params = if self.at(&TokenKind::LBrace) {
            self.parse_param_block()
        } else { vec![] };
        let bind = self.parse_bind();
        Some(StepOpNode::ToolCall { tool_name, params, bind, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_infer(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'infer'
        let prompt = self.expect_string().ok()?;
        let mut with_vars = Vec::new();
        if self.try_consume(&TokenKind::KwWith) {
            // parse comma-separated var refs or idents
            loop {
                match self.peek_kind().clone() {
                    TokenKind::VarRef(path) => { self.advance(); with_vars.push(path); }
                    TokenKind::Ident(name) => { self.advance(); with_vars.push(name); }
                    _ => break,
                }
                if !self.try_consume(&TokenKind::Comma) { break; }
            }
        }
        let bind = self.parse_bind();
        Some(StepOpNode::LlmInfer { prompt, with_vars, max_tokens: None, temperature: None, bind, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_recall(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'recall'
        let namespace = self.expect_ident().ok()?;
        let params = if self.at(&TokenKind::LBrace) {
            self.parse_param_block()
        } else { vec![] };
        let query = params.iter().find(|p| p.key == "query").map(|p| p.value.clone())
            .unwrap_or_else(|| ExprNode::StringLit("*".into(), Span::default()));
        let limit = params.iter().find(|p| p.key == "limit").and_then(|p| {
            if let ExprNode::IntLit(n, _) = &p.value { Some(*n) } else { None }
        });
        let bind = self.parse_bind();
        Some(StepOpNode::MemRecall { namespace, query, limit, bind, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_remember(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'remember'
        let namespace = self.expect_ident().ok()?;
        let params = if self.at(&TokenKind::LBrace) {
            self.parse_param_block()
        } else { vec![] };
        let content = params.iter().find(|p| p.key == "content").map(|p| p.value.clone())
            .unwrap_or_else(|| ExprNode::NullLit(Span::default()));
        let tags: Vec<String> = params.iter()
            .filter(|p| p.key == "tag" || p.key == "tags")
            .filter_map(|p| if let ExprNode::StringLit(s, _) = &p.value { Some(s.clone()) } else { None })
            .collect();
        Some(StepOpNode::MemRemember { namespace, content, tags, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_set_var(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'set'
        let name = self.expect_ident().ok()?;
        let _ = self.expect(&TokenKind::Assign);
        let value = self.parse_expr().ok()?;
        Some(StepOpNode::SetVar { name, value, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_branch(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'branch'
        if self.expect(&TokenKind::LBrace).is_err() { return None; }

        let mut arms = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let arm_start = self.peek().span.start;
            if self.at(&TokenKind::KwWhen) {
                self.advance();
                if let Ok(pred) = self.parse_predicate() {
                    let _ = self.expect(&TokenKind::Arrow);
                    if let Ok(target) = self.expect_ident() {
                        arms.push(BranchArmNode { predicate: Some(pred), target, span: Span::new(arm_start, self.peek().span.end) });
                    }
                }
            } else if self.at(&TokenKind::KwOtherwise) {
                self.advance();
                let _ = self.expect(&TokenKind::Arrow);
                if let Ok(target) = self.expect_ident() {
                    arms.push(BranchArmNode { predicate: None, target, span: Span::new(arm_start, self.peek().span.end) });
                }
            } else {
                self.error_at_current("E_BAD_BRANCH", format!("expected 'when' or 'otherwise', found {:?}", self.peek_kind()));
                self.advance();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(StepOpNode::Branch { arms, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_transition(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'transition'
        let state = self.expect_ident().ok()?;
        Some(StepOpNode::Transition { state, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_emit_event(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'emit'
        let event = self.expect_ident().ok()?;
        let data = if self.at(&TokenKind::LBrace) {
            self.parse_param_block()
        } else { vec![] };
        Some(StepOpNode::EmitEvent { event, data, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_checkpoint(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'checkpoint'
        let label = self.expect_string().ok()?;
        Some(StepOpNode::Checkpoint { label, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_call_contract(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'call'
        let contract = self.expect_ident().ok()?;
        let params = if self.at(&TokenKind::LBrace) {
            self.parse_param_block()
        } else { vec![] };
        let bind = self.parse_bind();
        Some(StepOpNode::CallContract { contract, params, bind, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_send_message(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'send'
        let target = self.expect_ident().ok()?;
        let payload = if self.at(&TokenKind::LBrace) {
            self.parse_param_block()
        } else { vec![] };
        Some(StepOpNode::SendMessage { target, payload, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_wait_event(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'wait'
        let event = self.expect_ident().ok()?;
        let timeout = if let TokenKind::IntLit(n) = self.peek_kind() {
            let v = *n;
            self.advance();
            Some(v)
        } else { None };
        Some(StepOpNode::WaitEvent { event, timeout, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_parallel(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'parallel'
        if self.expect(&TokenKind::LBrace).is_err() { return None; }
        let mut ops = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            if let Some(op) = self.parse_step_op() {
                ops.push(op);
            } else {
                self.advance();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        Some(StepOpNode::Parallel { ops, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_saga(&mut self, start: Pos) -> Option<StepOpNode> {
        self.advance(); // consume 'saga'
        if self.expect(&TokenKind::LBrace).is_err() { return None; }
        let forward = self.parse_step_op();
        let compensate = self.parse_step_op();
        let _ = self.try_consume(&TokenKind::RBrace);
        if let (Some(f), Some(c)) = (forward, compensate) {
            Some(StepOpNode::Saga { forward: Box::new(f), compensate: Box::new(c), span: Span::new(start, self.peek().span.end) })
        } else { None }
    }

    // ═══════════════════════════════════════════════════════════════
    // Constitutional Block Parsers
    // ═══════════════════════════════════════════════════════════════

    // ── Solution Block ──────────────────────────────────────────────
    // solution claims_review version "1.0.0" { domain healthcare, owner "claims-team" }

    fn parse_solution_block(&mut self) -> Option<SolutionNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'solution'
        
        let name = self.expect_ident().unwrap_or_else(|_| "unnamed".into());
        
        // Optional: version "x.y.z"
        let version = if self.at(&TokenKind::KwVersion) {
            self.advance();
            self.expect_string().ok()
        } else { None };
        
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut domain = None;
        let mut owner = None;
        let mut description = None;
        let mut tags = Vec::new();
        
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.peek_kind().clone() {
                TokenKind::KwDomain => {
                    self.advance();
                    domain = self.expect_ident().ok().or_else(|| self.expect_string().ok());
                }
                TokenKind::KwOwner => {
                    self.advance();
                    owner = self.expect_string().ok();
                }
                TokenKind::Ident(key) if key == "description" => {
                    self.advance();
                    let _ = self.try_consume(&TokenKind::Colon);
                    description = self.expect_string().ok();
                }
                TokenKind::Ident(key) if key == "tags" => {
                    self.advance();
                    let _ = self.try_consume(&TokenKind::Colon);
                    if self.try_consume(&TokenKind::LBracket) {
                        while !self.at(&TokenKind::RBracket) && !self.at_eof() {
                            if let Ok(tag) = self.expect_ident() {
                                tags.push(tag);
                            } else if let Ok(tag) = self.expect_string() {
                                tags.push(tag);
                            }
                            self.try_consume(&TokenKind::Comma);
                        }
                        let _ = self.try_consume(&TokenKind::RBracket);
                    }
                }
                _ => { self.advance(); }
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(SolutionNode { name, version, domain, owner, description, tags, span: Span::new(start, self.peek().span.end) })
    }

    // ── Import Declaration ──────────────────────────────────────────
    // import schema PatientRecord
    // import policy_pack hipaa_baseline
    // import tool_contract payer_policy_check

    fn parse_import_decl(&mut self) -> Option<ImportDeclNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'import'
        
        let kind = match self.peek_kind().clone() {
            TokenKind::KwSchema => { self.advance(); ImportKind::Schema }
            TokenKind::KwPolicyPack => { self.advance(); ImportKind::PolicyPack }
            TokenKind::KwToolContract => { self.advance(); ImportKind::ToolContract }
            _ => {
                self.error_at_current("E_BAD_IMPORT", format!("expected schema/policy_pack/tool_contract, found {:?}", self.peek_kind()));
                return None;
            }
        };
        
        let name = self.expect_ident().ok()?;
        let alias = if self.try_consume(&TokenKind::KwAs) {
            self.expect_ident().ok()
        } else { None };
        
        Some(ImportDeclNode { kind, name, alias, span: Span::new(start, self.peek().span.end) })
    }

    // ── Capabilities Block ──────────────────────────────────────────
    // capabilities { tool X advisory, memory Y readonly, protocol native }

    fn parse_capabilities_block(&mut self) -> Option<CapabilitiesNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'capabilities'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut capabilities = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let cap_start = self.peek().span.start;
            let kind = match self.peek_kind().clone() {
                TokenKind::KwTool => { self.advance(); CapabilityKind::Tool }
                TokenKind::KwMemory => { self.advance(); CapabilityKind::Memory }
                TokenKind::KwProtocol => { self.advance(); CapabilityKind::Protocol }
                TokenKind::KwModel => { self.advance(); CapabilityKind::Model }
                TokenKind::KwReviewQueue => { self.advance(); CapabilityKind::ReviewQueue }
                _ => {
                    self.error_at_current("E_BAD_CAPABILITY", format!("expected tool/memory/protocol/model/review_queue, found {:?}", self.peek_kind()));
                    self.advance();
                    continue;
                }
            };
            
            let name = self.expect_ident().unwrap_or_else(|_| "unnamed".into());
            
            let modifier = match self.peek_kind().clone() {
                TokenKind::KwAdvisory => { self.advance(); Some(CapabilityModifier::Advisory) }
                TokenKind::KwBinding => { self.advance(); Some(CapabilityModifier::Binding) }
                TokenKind::KwReadonly => { self.advance(); Some(CapabilityModifier::Readonly) }
                TokenKind::KwReadwrite => { self.advance(); Some(CapabilityModifier::Readwrite) }
                _ => None
            };
            
            capabilities.push(CapabilityDeclNode { kind, name, modifier, span: Span::new(cap_start, self.peek().span.end) });
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(CapabilitiesNode { capabilities, span: Span::new(start, self.peek().span.end) })
    }

    // ── Policy Block ────────────────────────────────────────────────
    // policy { require audit_trail, deny export_pii outside case_context }

    fn parse_policy_block(&mut self) -> Option<PolicyNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'policy'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut rules = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let rule_start = self.peek().span.start;
            let kind = match self.peek_kind().clone() {
                TokenKind::KwRequire => { self.advance(); PolicyRuleKind::Require }
                TokenKind::KwDeny => { self.advance(); PolicyRuleKind::Deny }
                TokenKind::KwAllow => { self.advance(); PolicyRuleKind::Allow }
                _ => {
                    self.error_at_current("E_BAD_POLICY", format!("expected require/deny/allow, found {:?}", self.peek_kind()));
                    self.advance();
                    continue;
                }
            };
            
            let subject = self.expect_ident().unwrap_or_else(|_| "unknown".into());
            
            // Optional condition: when <predicate>
            let condition = if self.at(&TokenKind::KwWhen) {
                self.advance();
                self.parse_predicate().ok()
            } else { None };
            
            // Optional modifier: outside/unless/conforms
            let modifier = if self.at(&TokenKind::KwOutside) {
                self.advance();
                let target = self.expect_ident().unwrap_or_else(|_| "unknown".into());
                Some(PolicyModifier { kind: PolicyModifierKind::Outside, target, span: Span::new(rule_start, self.peek().span.end) })
            } else if self.at(&TokenKind::KwUnless) {
                self.advance();
                let target = self.expect_ident().unwrap_or_else(|_| "unknown".into());
                Some(PolicyModifier { kind: PolicyModifierKind::Unless, target, span: Span::new(rule_start, self.peek().span.end) })
            } else if self.at(&TokenKind::KwConforms) {
                self.advance();
                let target = self.expect_ident().unwrap_or_else(|_| "unknown".into());
                Some(PolicyModifier { kind: PolicyModifierKind::Conforms, target, span: Span::new(rule_start, self.peek().span.end) })
            } else { None };
            
            rules.push(PolicyRuleNode { kind, subject, condition, modifier, span: Span::new(rule_start, self.peek().span.end) });
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(PolicyNode { rules, span: Span::new(start, self.peek().span.end) })
    }

    // ── Flow Block ──────────────────────────────────────────────────
    // flow { stage validate { require X, call Y } stage analyze { ... } }

    fn parse_flow_block(&mut self) -> Option<FlowNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'flow'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut stages = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            if self.at(&TokenKind::KwStage) {
                if let Some(stage) = self.parse_stage() {
                    stages.push(stage);
                }
            } else {
                self.error_at_current("E_BAD_FLOW", format!("expected 'stage', found {:?}", self.peek_kind()));
                self.advance();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(FlowNode { stages, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_stage(&mut self) -> Option<StageNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'stage'
        let name = self.expect_ident().unwrap_or_else(|_| "unnamed".into());
        if self.expect(&TokenKind::LBrace).is_err() { return None; }
        
        let mut ops = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            if let Some(op) = self.parse_stage_op() {
                ops.push(op);
            } else {
                self.advance();
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(StageNode { name, ops, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_stage_op(&mut self) -> Option<StageOpNode> {
        let start = self.peek().span.start;
        match self.peek_kind().clone() {
            TokenKind::KwRequire => {
                self.advance();
                let predicate = self.parse_predicate().ok()?;
                Some(StageOpNode::Require { predicate, span: Span::new(start, self.peek().span.end) })
            }
            TokenKind::KwCall => {
                self.advance();
                let tool = self.expect_ident().ok()?;
                let _ = self.try_consume(&TokenKind::KwWith);
                let params = if self.at(&TokenKind::LBrace) { self.parse_param_block() } else { vec![] };
                let bind = if self.try_consume(&TokenKind::KwAs) { self.expect_ident().ok() } else { None };
                Some(StageOpNode::Call { tool, params, bind, span: Span::new(start, self.peek().span.end) })
            }
            TokenKind::KwEmit => {
                self.advance();
                let output = self.expect_ident().ok()?;
                let data = if self.at(&TokenKind::LBrace) { self.parse_param_block() } else { vec![] };
                Some(StageOpNode::Emit { output, data, span: Span::new(start, self.peek().span.end) })
            }
            TokenKind::KwRoute => {
                self.advance();
                // Skip optional "to" keyword
                if let TokenKind::Ident(ref s) = self.peek_kind() {
                    if s == "to" { self.advance(); }
                }
                let target = self.expect_ident().ok()?;
                let outcome = if matches!(self.peek_kind(), TokenKind::Ident(_)) { self.expect_ident().ok() } else { None };
                Some(StageOpNode::Route { target, outcome, span: Span::new(start, self.peek().span.end) })
            }
            TokenKind::KwFail => {
                self.advance();
                let message = self.expect_string().unwrap_or_else(|_| "failure".into());
                let outcome = if matches!(self.peek_kind(), TokenKind::Ident(_)) { self.expect_ident().ok() } else { None };
                Some(StageOpNode::Fail { message, outcome, span: Span::new(start, self.peek().span.end) })
            }
            TokenKind::KwWhen => {
                self.advance();
                let predicate = self.parse_predicate().ok()?;
                if self.expect(&TokenKind::LBrace).is_err() { return None; }
                let mut body = Vec::new();
                while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::KwOtherwise) && !self.at_eof() {
                    if let Some(op) = self.parse_stage_op() { body.push(op); } else { self.advance(); }
                }
                let _ = self.try_consume(&TokenKind::RBrace);
                let otherwise = if self.at(&TokenKind::KwOtherwise) {
                    self.advance();
                    if self.expect(&TokenKind::LBrace).is_err() { return None; }
                    let mut else_body = Vec::new();
                    while !self.at(&TokenKind::RBrace) && !self.at_eof() {
                        if let Some(op) = self.parse_stage_op() { else_body.push(op); } else { self.advance(); }
                    }
                    let _ = self.try_consume(&TokenKind::RBrace);
                    Some(else_body)
                } else { None };
                Some(StageOpNode::When { predicate, body, otherwise, span: Span::new(start, self.peek().span.end) })
            }
            TokenKind::KwSet => {
                self.advance();
                let name = self.expect_ident().ok()?;
                let _ = self.expect(&TokenKind::Assign);
                let value = self.parse_expr().ok()?;
                Some(StageOpNode::Bind { name, value, span: Span::new(start, self.peek().span.end) })
            }
            _ => None
        }
    }

    // ── Evidence Block ──────────────────────────────────────────────
    // evidence { record input_hash, verify chain_integrity }

    fn parse_evidence_block(&mut self) -> Option<EvidenceNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'evidence'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut entries = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let entry_start = self.peek().span.start;
            let kind = match self.peek_kind().clone() {
                TokenKind::KwRecord => { self.advance(); EvidenceKind::Record }
                TokenKind::KwVerify => { self.advance(); EvidenceKind::Verify }
                _ => {
                    self.error_at_current("E_BAD_EVIDENCE", format!("expected record/verify, found {:?}", self.peek_kind()));
                    self.advance();
                    continue;
                }
            };
            let subject = self.expect_ident().unwrap_or_else(|_| "unknown".into());
            entries.push(EvidenceEntryNode { kind, subject, span: Span::new(entry_start, self.peek().span.end) });
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(EvidenceNode { entries, span: Span::new(start, self.peek().span.end) })
    }

    // ── Outcomes Block ──────────────────────────────────────────────
    // outcomes { approve, reject, escalate, blocked }

    fn parse_outcomes_block(&mut self) -> Option<OutcomesNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'outcomes'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut outcomes = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            if let Ok(name) = self.expect_ident() {
                outcomes.push(name);
            } else {
                self.advance();
            }
            self.try_consume(&TokenKind::Comma);
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(OutcomesNode { outcomes, span: Span::new(start, self.peek().span.end) })
    }

    // ── Review Block ────────────────────────────────────────────────
    // review human_review { required when confidence < 0.80, queue claims_manual_review }

    fn parse_review_block(&mut self) -> Option<ReviewNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'review'
        let name = self.expect_ident().unwrap_or_else(|_| "unnamed".into());
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut required_when = None;
        let mut queue = None;
        let mut on_timeout = None;
        
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            match self.peek_kind().clone() {
                TokenKind::KwRequired => {
                    self.advance();
                    if self.try_consume(&TokenKind::KwWhen) {
                        required_when = self.parse_predicate().ok();
                    }
                }
                TokenKind::KwQueue => {
                    self.advance();
                    queue = self.expect_ident().ok();
                }
                TokenKind::KwOnTimeout => {
                    self.advance();
                    let action = self.expect_ident().unwrap_or_else(|_| "route".into());
                    let _ = self.try_consume(&TokenKind::Ident("to".into()));
                    let target = self.expect_ident().unwrap_or_else(|_| "blocked".into());
                    on_timeout = Some(ReviewTimeoutAction { action, target, span: Span::new(start, self.peek().span.end) });
                }
                _ => { self.advance(); }
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(ReviewNode { name, required_when, queue, on_timeout, span: Span::new(start, self.peek().span.end) })
    }

    // ── Output Block ────────────────────────────────────────────────
    // output {
    //     decision: enum { approve, reject, escalate } required
    //     confidence: float range 0.0..1.0
    //     reasoning: text required evidence_ref
    //     supporting_docs: List<document> min_items 1
    // }

    fn parse_output_block(&mut self) -> Option<OutputBlockNode> {
        let start = self.peek().span.start;
        self.advance(); // consume 'output'
        if self.expect(&TokenKind::LBrace).is_err() { self.synchronize_block(); return None; }
        
        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            if let Some(field) = self.parse_output_field() {
                fields.push(field);
            } else {
                self.advance(); // skip unknown token
            }
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        
        Some(OutputBlockNode { fields, span: Span::new(start, self.peek().span.end) })
    }

    fn parse_output_field(&mut self) -> Option<OutputFieldNode> {
        let start = self.peek().span.start;
        
        // field_name: type [required] [constraints...] [evidence_ref] ["description"]
        let name = self.expect_ident().ok()?;
        let _ = self.expect(&TokenKind::Colon);
        let type_ann = self.parse_type()?;
        
        let mut required = false;
        let mut constraints = Vec::new();
        let mut evidence_ref = false;
        let mut description = None;
        
        // Parse modifiers and constraints
        loop {
            match self.peek_kind().clone() {
                TokenKind::KwRequired => {
                    self.advance();
                    required = true;
                }
                TokenKind::KwRange => {
                    self.advance();
                    // Parse range: min..max or min.. or ..max
                    let min = if !self.at(&TokenKind::DotDot) {
                        Some(self.parse_expr().ok()?)
                    } else { None };
                    let _ = self.expect(&TokenKind::DotDot);
                    let max = if !self.at(&TokenKind::KwRequired) && !self.at(&TokenKind::RBrace) 
                        && !self.at(&TokenKind::Newline) && !matches!(self.peek_kind(), TokenKind::Ident(_))
                        && !self.at(&TokenKind::KwEvidenceRef) && !matches!(self.peek_kind(), TokenKind::StringLit(_)) {
                        Some(self.parse_expr().ok()?)
                    } else { None };
                    constraints.push(ValidationConstraint::Range { min, max });
                }
                TokenKind::KwMinItems => {
                    self.advance();
                    if let TokenKind::IntLit(n) = self.peek_kind().clone() {
                        self.advance();
                        constraints.push(ValidationConstraint::MinItems(n));
                    }
                }
                TokenKind::KwMaxItems => {
                    self.advance();
                    if let TokenKind::IntLit(n) = self.peek_kind().clone() {
                        self.advance();
                        constraints.push(ValidationConstraint::MaxItems(n));
                    }
                }
                TokenKind::KwMinLength => {
                    self.advance();
                    if let TokenKind::IntLit(n) = self.peek_kind().clone() {
                        self.advance();
                        constraints.push(ValidationConstraint::MinLength(n));
                    }
                }
                TokenKind::KwMaxLength => {
                    self.advance();
                    if let TokenKind::IntLit(n) = self.peek_kind().clone() {
                        self.advance();
                        constraints.push(ValidationConstraint::MaxLength(n));
                    }
                }
                TokenKind::KwPattern => {
                    self.advance();
                    if let Ok(pat) = self.expect_string() {
                        constraints.push(ValidationConstraint::Pattern(pat));
                    }
                }
                TokenKind::KwOneOf => {
                    self.advance();
                    let _ = self.expect(&TokenKind::LBracket);
                    let mut values = Vec::new();
                    while !self.at(&TokenKind::RBracket) && !self.at_eof() {
                        if let Ok(expr) = self.parse_expr() {
                            values.push(expr);
                        }
                        if !self.try_consume(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let _ = self.expect(&TokenKind::RBracket);
                    constraints.push(ValidationConstraint::OneOf(values));
                }
                TokenKind::KwEvidenceRef => {
                    self.advance();
                    evidence_ref = true;
                }
                TokenKind::StringLit(_) => {
                    description = self.expect_string().ok();
                    break; // description is always last
                }
                _ => break,
            }
        }
        
        Some(OutputFieldNode {
            name,
            type_ann,
            required,
            constraints,
            evidence_ref,
            description,
            span: Span::new(start, self.peek().span.end),
        })
    }

    // ═══════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════

    fn parse_bind(&mut self) -> Option<String> {
        if self.try_consume(&TokenKind::Arrow) {
            self.expect_ident().ok()
        } else { None }
    }

    fn parse_param_block(&mut self) -> Vec<ParamNode> {
        let mut params = Vec::new();
        self.advance(); // consume {
        while !self.at(&TokenKind::RBrace) && !self.at_eof() {
            let s = self.peek().span.start;
            // Accept both identifiers and keywords as param keys
            let key = match self.peek_kind().clone() {
                TokenKind::Ident(name) => { self.advance(); Some(name) }
                _ if self.peek().is_keyword() => {
                    let name = self.peek().lexeme.clone();
                    self.advance();
                    Some(name)
                }
                _ => {
                    self.error_at_current("E_EXPECTED_KEY", format!("expected param key, found {:?}", self.peek_kind()));
                    self.advance();
                    None
                }
            };
            if let Some(key) = key {
                let _ = self.expect(&TokenKind::Colon);
                if let Ok(value) = self.parse_expr() {
                    params.push(ParamNode { key, value, span: Span::new(s, self.peek().span.end) });
                }
            }
            self.try_consume(&TokenKind::Comma);
        }
        let _ = self.try_consume(&TokenKind::RBrace);
        params
    }

    fn parse_expr(&mut self) -> Result<ExprNode, ()> {
        let span = self.peek().span;
        match self.peek_kind().clone() {
            TokenKind::StringLit(s) => { self.advance(); Ok(ExprNode::StringLit(s, span)) }
            TokenKind::IntLit(n) => { self.advance(); Ok(ExprNode::IntLit(n, span)) }
            TokenKind::FloatLit(f) => { self.advance(); Ok(ExprNode::FloatLit(f, span)) }
            TokenKind::BoolTrue => { self.advance(); Ok(ExprNode::BoolLit(true, span)) }
            TokenKind::BoolFalse => { self.advance(); Ok(ExprNode::BoolLit(false, span)) }
            TokenKind::NullLit => { self.advance(); Ok(ExprNode::NullLit(span)) }
            TokenKind::VarRef(path) => { self.advance(); Ok(ExprNode::VarRef(path, span)) }
            TokenKind::Ident(name) => { self.advance(); Ok(ExprNode::Ident(name, span)) }
            TokenKind::LBrace => {
                let params = self.parse_param_block();
                Ok(ExprNode::ObjectLit(params, span))
            }
            TokenKind::LBracket => {
                self.advance();
                let mut items = Vec::new();
                while !self.at(&TokenKind::RBracket) && !self.at_eof() {
                    items.push(self.parse_expr()?);
                    self.try_consume(&TokenKind::Comma);
                }
                let _ = self.try_consume(&TokenKind::RBracket);
                Ok(ExprNode::ListLit(items, span))
            }
            _ => {
                self.error_at_current("E_BAD_EXPR", format!("expected expression, found {:?}", self.peek_kind()));
                Err(())
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_contract() {
        let src = r#"contract test {
            identity {
                name: "test"
                version: "1.0.0"
            }
            interface {
                input x: String required
                output y: Json
                tool my_tool
                event done
            }
            state {
                initial start
                terminal finished
                start -> finished on complete
            }
            governance {
                require x is present
                ensure y is present
                roles [admin, user]
                clearance "high"
                compliance [hipaa, gdpr]
            }
            budget {
                tokens: 4096
                cost_usd: 0.50
                tool_calls: 10
            }
            memory {
                use medical_history as history
                use guidelines
            }
            behavior {
                step intake {
                    tool my_tool { id: ${x} } -> result
                    set y = ${result}
                    transition finished
                    emit done { data: ${result} }
                }
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        assert_eq!(contract.name, "test");
        assert_eq!(contract.blocks.len(), 7);

        // Check identity
        if let BlockNode::Identity(id) = &contract.blocks[0] {
            assert_eq!(id.entries.len(), 2);
            assert_eq!(id.entries[0].0, "name");
            assert_eq!(id.entries[0].1, "test");
        } else { panic!("expected identity block"); }

        // Check interface
        if let BlockNode::Interface(iface) = &contract.blocks[1] {
            assert_eq!(iface.inputs.len(), 1);
            assert_eq!(iface.inputs[0].name, "x");
            assert!(iface.inputs[0].required);
            assert_eq!(iface.outputs.len(), 1);
            assert_eq!(iface.tools.len(), 1);
            assert_eq!(iface.events.len(), 1);
        } else { panic!("expected interface block"); }

        // Check state
        if let BlockNode::State(state) = &contract.blocks[2] {
            assert_eq!(state.states.len(), 2);
            assert_eq!(state.transitions.len(), 1);
            assert_eq!(state.transitions[0].from, "start");
            assert_eq!(state.transitions[0].to, "finished");
        } else { panic!("expected state block"); }

        // Check governance
        if let BlockNode::Governance(gov) = &contract.blocks[3] {
            assert_eq!(gov.requires.len(), 1);
            assert_eq!(gov.ensures.len(), 1);
            assert_eq!(gov.roles, vec!["admin", "user"]);
            assert_eq!(gov.compliance, vec!["hipaa", "gdpr"]);
        } else { panic!("expected governance block"); }

        // Check budget
        if let BlockNode::Budget(budget) = &contract.blocks[4] {
            assert_eq!(budget.entries.len(), 3);
        } else { panic!("expected budget block"); }

        // Check memory
        if let BlockNode::Memory(mem) = &contract.blocks[5] {
            assert_eq!(mem.uses.len(), 2);
            assert_eq!(mem.uses[0].namespace, "medical_history");
            assert_eq!(mem.uses[0].alias, "history");
        } else { panic!("expected memory block"); }

        // Check behavior
        if let BlockNode::Behavior(beh) = &contract.blocks[6] {
            assert_eq!(beh.steps.len(), 1);
            assert_eq!(beh.steps[0].id, "intake");
            assert_eq!(beh.steps[0].ops.len(), 4);
        } else { panic!("expected behavior block"); }
    }

    #[test]
    fn test_parse_complex_predicates() {
        let src = r#"contract pred_test {
            governance {
                require patient_id is present
                require severity > 8.0 and priority == "critical"
                ensure not status in ["cancelled", "invalid"]
                invariant budget.tokens > 0 or budget.cost_usd > 0.0
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Governance(gov) = &contract.blocks[0] {
            assert_eq!(gov.requires.len(), 2);
            assert_eq!(gov.ensures.len(), 1);
            assert_eq!(gov.invariants.len(), 1);
            // Check 'and' predicate
            if let PredicateNode::And { .. } = &gov.requires[1] {} else { panic!("expected And predicate"); }
            // Check 'not' predicate
            if let PredicateNode::Not { .. } = &gov.ensures[0] {} else { panic!("expected Not predicate"); }
            // Check 'or' predicate
            if let PredicateNode::Or { .. } = &gov.invariants[0] {} else { panic!("expected Or predicate"); }
        } else { panic!("expected governance"); }
    }

    #[test]
    fn test_parse_branch_step() {
        let src = r#"contract branch_test {
            behavior {
                step route {
                    branch {
                        when ${score} > 8.0 -> escalate
                        when ${score} > 5.0 -> normal
                        otherwise -> low
                    }
                }
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Behavior(beh) = &contract.blocks[0] {
            if let StepOpNode::Branch { arms, .. } = &beh.steps[0].ops[0] {
                assert_eq!(arms.len(), 3);
                assert!(arms[0].predicate.is_some()); // when score > 8.0
                assert!(arms[1].predicate.is_some()); // when score > 5.0
                assert!(arms[2].predicate.is_none()); // otherwise
                assert_eq!(arms[0].target, "escalate");
                assert_eq!(arms[2].target, "low");
            } else { panic!("expected branch"); }
        } else { panic!("expected behavior"); }
    }

    #[test]
    fn test_parse_all_step_ops() {
        let src = r#"contract ops_test {
            behavior {
                step all_ops {
                    tool lookup { id: "123" } -> patient
                    infer "assess" with ${patient} -> assessment
                    recall history { query: "past visits", limit: 5 } -> records
                    remember notes { content: ${assessment} }
                    set priority = "high"
                    checkpoint "before_routing"
                    transition active
                    emit completed { result: ${assessment} }
                    call sub_contract { input: ${patient} } -> sub_result
                    send other_agent { data: ${assessment} }
                    wait approval 30000
                }
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Behavior(beh) = &contract.blocks[0] {
            assert_eq!(beh.steps[0].ops.len(), 11);
            assert!(matches!(beh.steps[0].ops[0], StepOpNode::ToolCall { .. }));
            assert!(matches!(beh.steps[0].ops[1], StepOpNode::LlmInfer { .. }));
            assert!(matches!(beh.steps[0].ops[2], StepOpNode::MemRecall { .. }));
            assert!(matches!(beh.steps[0].ops[3], StepOpNode::MemRemember { .. }));
            assert!(matches!(beh.steps[0].ops[4], StepOpNode::SetVar { .. }));
            assert!(matches!(beh.steps[0].ops[5], StepOpNode::Checkpoint { .. }));
            assert!(matches!(beh.steps[0].ops[6], StepOpNode::Transition { .. }));
            assert!(matches!(beh.steps[0].ops[7], StepOpNode::EmitEvent { .. }));
            assert!(matches!(beh.steps[0].ops[8], StepOpNode::CallContract { .. }));
            assert!(matches!(beh.steps[0].ops[9], StepOpNode::SendMessage { .. }));
            assert!(matches!(beh.steps[0].ops[10], StepOpNode::WaitEvent { .. }));
        } else { panic!("expected behavior"); }
    }

    #[test]
    fn test_parse_type_annotations() {
        let src = r#"contract type_test {
            interface {
                input a: String required
                input b: Int optional
                input c: Float required
                input d: Bool required
                input e: Json required
                input f: List<String> required
                input g: Map<String, Int> required
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Interface(iface) = &contract.blocks[0] {
            assert_eq!(iface.inputs.len(), 7);
            assert_eq!(iface.inputs[0].type_ann, TypeNode::Primitive(PrimitiveType::String));
            assert_eq!(iface.inputs[1].type_ann, TypeNode::Primitive(PrimitiveType::Int));
            assert!(!iface.inputs[1].required);
            assert_eq!(iface.inputs[5].type_ann, TypeNode::List(Box::new(TypeNode::Primitive(PrimitiveType::String))));
            assert_eq!(iface.inputs[6].type_ann, TypeNode::Map(
                Box::new(TypeNode::Primitive(PrimitiveType::String)),
                Box::new(TypeNode::Primitive(PrimitiveType::Int)),
            ));
        } else { panic!("expected interface"); }
    }

    #[test]
    fn test_parse_parallel_and_saga() {
        let src = r#"contract adv_test {
            behavior {
                step concurrent {
                    parallel {
                        tool check_a { id: "1" } -> a
                        tool check_b { id: "2" } -> b
                    }
                }
                step compensated {
                    saga {
                        tool reserve { id: "1" } -> reservation
                        tool cancel { id: ${reservation} }
                    }
                }
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Behavior(beh) = &contract.blocks[0] {
            assert_eq!(beh.steps.len(), 2);
            if let StepOpNode::Parallel { ops, .. } = &beh.steps[0].ops[0] {
                assert_eq!(ops.len(), 2);
            } else { panic!("expected parallel"); }
            if let StepOpNode::Saga { forward, compensate, .. } = &beh.steps[1].ops[0] {
                assert!(matches!(**forward, StepOpNode::ToolCall { .. }));
                assert!(matches!(**compensate, StepOpNode::ToolCall { .. }));
            } else { panic!("expected saga"); }
        } else { panic!("expected behavior"); }
    }

    #[test]
    fn test_error_recovery_missing_brace() {
        // Missing closing braces — parser should still produce a result
        // but may have errors or incomplete blocks
        let result = CclParser::parse("contract test { identity { name: \"test\"");
        // Parser may succeed with partial output or fail with errors; either is acceptable
        // The key is it doesn't panic
        match result {
            Ok(contract) => assert_eq!(contract.name, "test"),
            Err(errors) => assert!(!errors.is_empty()),
        }
    }

    #[test]
    fn test_error_bad_block() {
        let result = CclParser::parse("contract test { foobar { } }");
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════════════════
    // Constitutional Block Tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_solution_block() {
        let src = r#"contract claims_review {
            solution claims_review version "1.0.0" {
                domain healthcare
                owner "claims-team"
                description: "Claims review solution"
                tags: [medical, insurance, review]
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Solution(sol) = &contract.blocks[0] {
            assert_eq!(sol.name, "claims_review");
            assert_eq!(sol.version, Some("1.0.0".to_string()));
            assert_eq!(sol.domain, Some("healthcare".to_string()));
            assert_eq!(sol.owner, Some("claims-team".to_string()));
            assert_eq!(sol.description, Some("Claims review solution".to_string()));
            assert_eq!(sol.tags, vec!["medical", "insurance", "review"]);
        } else { panic!("expected solution block"); }
    }

    #[test]
    fn test_parse_imports() {
        let src = r#"contract test {
            import schema PatientRecord
            import policy_pack hipaa_baseline
            import tool_contract payer_policy_check as policy_check
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Imports(imports) = &contract.blocks[0] {
            assert_eq!(imports.imports.len(), 3);
            assert_eq!(imports.imports[0].kind, ImportKind::Schema);
            assert_eq!(imports.imports[0].name, "PatientRecord");
            assert_eq!(imports.imports[1].kind, ImportKind::PolicyPack);
            assert_eq!(imports.imports[1].name, "hipaa_baseline");
            assert_eq!(imports.imports[2].kind, ImportKind::ToolContract);
            assert_eq!(imports.imports[2].name, "payer_policy_check");
            assert_eq!(imports.imports[2].alias, Some("policy_check".to_string()));
        } else { panic!("expected imports block"); }
    }

    #[test]
    fn test_parse_capabilities_block() {
        let src = r#"contract test {
            capabilities {
                tool icd10_lookup advisory
                tool payer_policy_check binding
                memory payer_guidelines readonly
                memory case_context readwrite
                protocol native
                model decision_model
                review_queue claims_manual_review
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Capabilities(caps) = &contract.blocks[0] {
            assert_eq!(caps.capabilities.len(), 7);
            assert_eq!(caps.capabilities[0].kind, CapabilityKind::Tool);
            assert_eq!(caps.capabilities[0].name, "icd10_lookup");
            assert_eq!(caps.capabilities[0].modifier, Some(CapabilityModifier::Advisory));
            assert_eq!(caps.capabilities[1].modifier, Some(CapabilityModifier::Binding));
            assert_eq!(caps.capabilities[2].kind, CapabilityKind::Memory);
            assert_eq!(caps.capabilities[2].modifier, Some(CapabilityModifier::Readonly));
            assert_eq!(caps.capabilities[3].modifier, Some(CapabilityModifier::Readwrite));
            assert_eq!(caps.capabilities[4].kind, CapabilityKind::Protocol);
            assert_eq!(caps.capabilities[5].kind, CapabilityKind::Model);
            assert_eq!(caps.capabilities[6].kind, CapabilityKind::ReviewQueue);
        } else { panic!("expected capabilities block"); }
    }

    #[test]
    fn test_parse_policy_block() {
        let src = r#"contract test {
            policy {
                require audit_trail
                require human_review when confidence < 0.80
                deny export_pii outside case_context
                deny tool_external unless approved
                allow override conforms admin_override_schema
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Policy(policy) = &contract.blocks[0] {
            assert_eq!(policy.rules.len(), 5);
            assert_eq!(policy.rules[0].kind, PolicyRuleKind::Require);
            assert_eq!(policy.rules[0].subject, "audit_trail");
            assert_eq!(policy.rules[1].kind, PolicyRuleKind::Require);
            assert!(policy.rules[1].condition.is_some());
            assert_eq!(policy.rules[2].kind, PolicyRuleKind::Deny);
            assert!(policy.rules[2].modifier.is_some());
            assert_eq!(policy.rules[2].modifier.as_ref().unwrap().kind, PolicyModifierKind::Outside);
            assert_eq!(policy.rules[3].modifier.as_ref().unwrap().kind, PolicyModifierKind::Unless);
            assert_eq!(policy.rules[4].kind, PolicyRuleKind::Allow);
            assert_eq!(policy.rules[4].modifier.as_ref().unwrap().kind, PolicyModifierKind::Conforms);
        } else { panic!("expected policy block"); }
    }

    #[test]
    fn test_parse_flow_block() {
        let src = r#"contract test {
            flow {
                stage validate {
                    require claim_id is present
                    require patient_record is present
                }
                stage analyze {
                    call icd10_lookup with { code: ${diagnosis} } as diagnosis_result
                    call payer_policy_check { claim_id: ${claim_id} } as payer_result
                }
                stage decide {
                    when payer_result == false {
                        emit decision { status: "reject" }
                    } otherwise {
                        emit decision { status: "approve" }
                    }
                }
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Flow(flow) = &contract.blocks[0] {
            assert_eq!(flow.stages.len(), 3);
            assert_eq!(flow.stages[0].name, "validate");
            assert_eq!(flow.stages[0].ops.len(), 2);
            assert!(matches!(flow.stages[0].ops[0], StageOpNode::Require { .. }));
            assert_eq!(flow.stages[1].name, "analyze");
            assert_eq!(flow.stages[1].ops.len(), 2);
            assert!(matches!(flow.stages[1].ops[0], StageOpNode::Call { .. }));
            assert_eq!(flow.stages[2].name, "decide");
            assert!(matches!(flow.stages[2].ops[0], StageOpNode::When { .. }));
        } else { panic!("expected flow block"); }
    }

    #[test]
    fn test_parse_evidence_block() {
        let src = r#"contract test {
            evidence {
                record input_hash
                record tool_calls
                record policy_checks
                record state_transitions
                record decision_trace
                record output_hash
                verify chain_integrity
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Evidence(ev) = &contract.blocks[0] {
            assert_eq!(ev.entries.len(), 7);
            assert_eq!(ev.entries[0].kind, EvidenceKind::Record);
            assert_eq!(ev.entries[0].subject, "input_hash");
            assert_eq!(ev.entries[6].kind, EvidenceKind::Verify);
            assert_eq!(ev.entries[6].subject, "chain_integrity");
        } else { panic!("expected evidence block"); }
    }

    #[test]
    fn test_parse_outcomes_block() {
        let src = r#"contract test {
            outcomes {
                approve,
                reject,
                escalate,
                request_more_info,
                blocked
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Outcomes(out) = &contract.blocks[0] {
            assert_eq!(out.outcomes, vec!["approve", "reject", "escalate", "request_more_info", "blocked"]);
        } else { panic!("expected outcomes block"); }
    }

    #[test]
    fn test_parse_review_block() {
        let src = r#"contract test {
            review human_review {
                required when confidence < 0.80
                queue claims_manual_review
                on_timeout route to blocked
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Review(rev) = &contract.blocks[0] {
            assert_eq!(rev.name, "human_review");
            assert!(rev.required_when.is_some());
            assert_eq!(rev.queue, Some("claims_manual_review".to_string()));
            assert!(rev.on_timeout.is_some());
            assert_eq!(rev.on_timeout.as_ref().unwrap().action, "route");
            assert_eq!(rev.on_timeout.as_ref().unwrap().target, "blocked");
        } else { panic!("expected review block"); }
    }

    #[test]
    fn test_parse_full_constitutional_contract() {
        // Test a full contract with all constitutional blocks
        let src = r#"contract claims_review {
            solution claims_review version "1.0.0" {
                domain healthcare
                owner "claims-team"
            }
            
            import schema PatientRecord
            import policy_pack hipaa_baseline
            
            capabilities {
                tool icd10_lookup advisory
                memory payer_guidelines readonly
                protocol native
                review_queue claims_manual_review
            }
            
            policy {
                require audit_trail
                deny export_pii outside case_context
            }
            
            outcomes {
                approve, reject, escalate, blocked
            }
            
            flow {
                stage validate {
                    require claim_id is present
                }
                stage decide {
                    emit decision { status: "approve" }
                }
            }
            
            evidence {
                record input_hash
                verify chain_integrity
            }
            
            review human_review {
                required when confidence < 0.80
                queue claims_manual_review
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse full constitutional contract");
        assert_eq!(contract.name, "claims_review");
        
        // Count block types
        let mut solution_count = 0;
        let mut imports_count = 0;
        let mut capabilities_count = 0;
        let mut policy_count = 0;
        let mut outcomes_count = 0;
        let mut flow_count = 0;
        let mut evidence_count = 0;
        let mut review_count = 0;
        
        for block in &contract.blocks {
            match block {
                BlockNode::Solution(_) => solution_count += 1,
                BlockNode::Imports(_) => imports_count += 1,
                BlockNode::Capabilities(_) => capabilities_count += 1,
                BlockNode::Policy(_) => policy_count += 1,
                BlockNode::Outcomes(_) => outcomes_count += 1,
                BlockNode::Flow(_) => flow_count += 1,
                BlockNode::Evidence(_) => evidence_count += 1,
                BlockNode::Review(_) => review_count += 1,
                _ => {}
            }
        }
        
        assert_eq!(solution_count, 1);
        assert_eq!(imports_count, 1);
        assert_eq!(capabilities_count, 1);
        assert_eq!(policy_count, 1);
        assert_eq!(outcomes_count, 1);
        assert_eq!(flow_count, 1);
        assert_eq!(evidence_count, 1);
        assert_eq!(review_count, 1);
    }

    #[test]
    fn test_parse_output_block() {
        let src = r#"contract test {
            output {
                decision: enum { approve, reject, escalate } required
                confidence: float range 0.0..1.0
                reasoning: text required evidence_ref "Explanation for the decision"
                supporting_docs: List<document> min_items 1
                review_notes: string?
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Output(out) = &contract.blocks[0] {
            assert_eq!(out.fields.len(), 5);
            // decision field
            assert_eq!(out.fields[0].name, "decision");
            assert!(matches!(out.fields[0].type_ann, TypeNode::Enum(_)));
            assert!(out.fields[0].required);
            // confidence field
            assert_eq!(out.fields[1].name, "confidence");
            assert!(matches!(out.fields[1].type_ann, TypeNode::Primitive(PrimitiveType::Float)));
            assert_eq!(out.fields[1].constraints.len(), 1);
            // reasoning field
            assert_eq!(out.fields[2].name, "reasoning");
            assert!(out.fields[2].required);
            assert!(out.fields[2].evidence_ref);
            assert!(out.fields[2].description.is_some());
            // supporting_docs field
            assert_eq!(out.fields[3].name, "supporting_docs");
            assert!(matches!(out.fields[3].type_ann, TypeNode::List(_)));
            // review_notes field (optional)
            assert_eq!(out.fields[4].name, "review_notes");
            assert!(matches!(out.fields[4].type_ann, TypeNode::Optional(_)));
        } else { panic!("expected output block"); }
    }

    #[test]
    fn test_parse_extended_types() {
        let src = r#"contract test {
            interface {
                input patient_id: string required
                input visit_date: date required
                input visit_time: time?
                input notes: text
                input attachments: List<document>
                input metadata: trusted<json>
                input raw_input: untrusted<string>
                input ssn: pii<string>
                input tool_output: tool_result<json>
                input policy_check: policy_result
                input evidence: evidence_ref
                input patient: record<PatientRecord>
                output status: enum { active, inactive, pending }
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Interface(iface) = &contract.blocks[0] {
            assert_eq!(iface.inputs.len(), 12);
            // Check date type
            assert!(matches!(iface.inputs[1].type_ann, TypeNode::Primitive(PrimitiveType::Date)));
            // Check optional time
            assert!(matches!(iface.inputs[2].type_ann, TypeNode::Optional(_)));
            // Check text type
            assert!(matches!(iface.inputs[3].type_ann, TypeNode::Primitive(PrimitiveType::Text)));
            // Check List<document>
            if let TypeNode::List(inner) = &iface.inputs[4].type_ann {
                assert!(matches!(**inner, TypeNode::Primitive(PrimitiveType::Document)));
            } else { panic!("expected List type"); }
            // Check trusted<json>
            assert!(matches!(iface.inputs[5].type_ann, TypeNode::Trusted(_)));
            // Check untrusted<string>
            assert!(matches!(iface.inputs[6].type_ann, TypeNode::Untrusted(_)));
            // Check pii<string>
            assert!(matches!(iface.inputs[7].type_ann, TypeNode::Pii(_)));
            // Check tool_result<json>
            assert!(matches!(iface.inputs[8].type_ann, TypeNode::ToolResult(_)));
            // Check policy_result
            assert!(matches!(iface.inputs[9].type_ann, TypeNode::PolicyResult));
            // Check evidence_ref
            assert!(matches!(iface.inputs[10].type_ann, TypeNode::EvidenceRef));
            // Check record<T>
            assert!(matches!(iface.inputs[11].type_ann, TypeNode::Record(_)));
            // Check enum output
            assert!(matches!(iface.outputs[0].type_ann, TypeNode::Enum(_)));
        } else { panic!("expected interface block"); }
    }

    #[test]
    fn test_parse_validation_constraints() {
        let src = r#"contract test {
            output {
                score: int range 0..100
                name: string min_length 1 max_length 255
                tags: List<string> min_items 1 max_items 10
                email: string pattern "[a-z]+@[a-z]+\\.com"
            }
        }"#;
        let contract = CclParser::parse(src).expect("should parse");
        if let BlockNode::Output(out) = &contract.blocks[0] {
            assert_eq!(out.fields.len(), 4);
            // score with range
            assert_eq!(out.fields[0].constraints.len(), 1);
            assert!(matches!(out.fields[0].constraints[0], ValidationConstraint::Range { .. }));
            // name with min/max length
            assert_eq!(out.fields[1].constraints.len(), 2);
            assert!(matches!(out.fields[1].constraints[0], ValidationConstraint::MinLength(_)));
            assert!(matches!(out.fields[1].constraints[1], ValidationConstraint::MaxLength(_)));
            // tags with min/max items
            assert_eq!(out.fields[2].constraints.len(), 2);
            assert!(matches!(out.fields[2].constraints[0], ValidationConstraint::MinItems(_)));
            assert!(matches!(out.fields[2].constraints[1], ValidationConstraint::MaxItems(_)));
            // email with pattern
            assert_eq!(out.fields[3].constraints.len(), 1);
            assert!(matches!(out.fields[3].constraints[0], ValidationConstraint::Pattern(_)));
        } else { panic!("expected output block"); }
    }
}
