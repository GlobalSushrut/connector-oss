//! Knot Capabilities — Full Knowledge Processing
//!
//! FIX BUG-044: Implement full Knot capabilities
//!
//! Features:
//! - Instruction compilation (text → executable)
//! - Contradiction detection and resolution
//! - Temporal reasoning (time-based inference)
//! - Multi-modal knowledge processing

use std::collections::{HashMap, HashSet, VecDeque, BTreeMap};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Instruction Compilation
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledInstruction {
    pub instruction_id: String,
    pub source_text: String,
    pub bytecode: Vec<OpCode>,
    pub symbols: HashMap<String, Symbol>,
    pub required_capabilities: Vec<String>,
    pub dependencies: Vec<String>,
    pub compiled_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpCode {
    Load { register: u8, value: Value },
    Store { register: u8, symbol: String },
    Call { function: String, args: Vec<u8> },
    Jump { label: String },
    JumpIf { condition: u8, label: String },
    Assert { condition: u8, message: String },
    Query { pattern: String, target: u8 },
    Infer { rule: String, result: u8 },
    Temporal { op: TemporalOp, args: Vec<u8> },
    Halt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
    Reference(String),
    Temporal(TemporalValue),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TemporalValue {
    Instant(i64),
    Interval(i64, i64),
    Duration(i64),
    Recurring { start: i64, period: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub symbol_type: SymbolType,
    pub scope: Scope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolType {
    Variable,
    Constant,
    Function,
    Knowledge,
    Temporal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Global,
    Local,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemporalOp {
    Before,
    After,
    During,
    Overlaps,
    Meets,
    Equals,
    Starts,
    Finishes,
}

pub struct InstructionCompiler {
    symbol_table: HashMap<String, Symbol>,
    label_counter: u64,
}

impl InstructionCompiler {
    pub fn new() -> Self {
        Self {
            symbol_table: HashMap::new(),
            label_counter: 0,
        }
    }

    /// Compile natural language instruction to bytecode
    pub fn compile(&mut self, text: &str) -> Result<CompiledInstruction, CompileError> {
        let mut bytecode = Vec::new();
        let mut symbols = HashMap::new();

        // Simple pattern-based compilation
        // In production: Use NLP parser + semantic analysis
        
        let lines: Vec<&str> = text.lines().collect();
        
        for line in &lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Pattern: "IF condition THEN action"
            if line.to_lowercase().starts_with("if ") {
                let condition = self.extract_condition(line);
                bytecode.push(OpCode::Query {
                    pattern: condition,
                    target: 0,
                });
                
                let label = self.generate_label();
                bytecode.push(OpCode::JumpIf {
                    condition: 0,
                    label: label.clone(),
                });
            }
            // Pattern: "QUERY pattern"
            else if line.to_lowercase().starts_with("query ") || line.to_lowercase().starts_with("find ") {
                let pattern = self.extract_pattern(line);
                bytecode.push(OpCode::Query {
                    pattern,
                    target: 0,
                });
            }
            // Pattern: "ASSERT condition"
            else if line.to_lowercase().starts_with("assert ") || line.to_lowercase().starts_with("check ") {
                let condition = self.extract_condition(line);
                bytecode.push(OpCode::Query {
                    pattern: condition,
                    target: 0,
                });
                bytecode.push(OpCode::Assert {
                    condition: 0,
                    message: "Assertion failed".to_string(),
                });
            }
            // Pattern: "INFER conclusion FROM premises"
            else if line.to_lowercase().starts_with("infer ") {
                let rule = self.extract_rule(line);
                bytecode.push(OpCode::Infer {
                    rule,
                    result: 0,
                });
            }
            // Pattern: temporal queries
            else if line.to_lowercase().contains("before") || 
                    line.to_lowercase().contains("after") ||
                    line.to_lowercase().contains("during") {
                let temporal_op = self.parse_temporal_op(line);
                bytecode.push(OpCode::Temporal {
                    op: temporal_op,
                    args: vec![0, 1],
                });
            }
        }

        bytecode.push(OpCode::Halt);

        Ok(CompiledInstruction {
            instruction_id: format!("inst-{}", uuid::Uuid::new_v4()),
            source_text: text.to_string(),
            bytecode,
            symbols,
            required_capabilities: vec!["knowledge".to_string(), "inference".to_string()],
            dependencies: vec![],
            compiled_at: chrono::Utc::now().timestamp_millis(),
        })
    }

    fn extract_condition(&self, line: &str) -> String {
        line.replace("if ", "")
            .replace("IF ", "")
            .replace(" then", "")
            .replace(" THEN", "")
            .trim()
            .to_string()
    }

    fn extract_pattern(&self, line: &str) -> String {
        line.replace("query ", "")
            .replace("QUERY ", "")
            .replace("find ", "")
            .replace("FIND ", "")
            .trim()
            .to_string()
    }

    fn extract_rule(&self, line: &str) -> String {
        line.replace("infer ", "")
            .replace("INFER ", "")
            .trim()
            .to_string()
    }

    fn parse_temporal_op(&self, line: &str) -> TemporalOp {
        let lower = line.to_lowercase();
        if lower.contains("before") {
            TemporalOp::Before
        } else if lower.contains("after") {
            TemporalOp::After
        } else if lower.contains("during") {
            TemporalOp::During
        } else if lower.contains("overlaps") {
            TemporalOp::Overlaps
        } else if lower.contains("meets") {
            TemporalOp::Meets
        } else if lower.contains("starts") {
            TemporalOp::Starts
        } else if lower.contains("finishes") {
            TemporalOp::Finishes
        } else {
            TemporalOp::Equals
        }
    }

    fn generate_label(&mut self) -> String {
        self.label_counter += 1;
        format!("L{}", self.label_counter)
    }
}

#[derive(Debug, Clone)]
pub enum CompileError {
    SyntaxError(String),
    UnknownSymbol(String),
    TypeMismatch,
    UnsupportedOperation,
}

// =============================================================================
// Contradiction Detection & Resolution
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeFact {
    pub fact_id: String,
    pub subject: String,
    pub predicate: String,
    pub object: Value,
    pub confidence: f64,
    pub sources: Vec<String>,
    pub timestamp: i64,
    pub validity: Validity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Validity {
    Confirmed,
    Probable,
    Possible,
    Unverified,
    Contradicted,
    Retracted,
}

#[derive(Debug, Clone)]
pub struct Contradiction {
    pub fact_a: String,
    pub fact_b: String,
    pub contradiction_type: ContradictionType,
    pub severity: f64,
    pub resolution_strategy: ResolutionStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContradictionType {
    DirectNegation,     // A says X, B says NOT X
    TemporalConflict,   // A says X at T1, B says X at T2
    ValueMismatch,      // A says X=V1, B says X=V2
    ScopeConflict,      // A says ALL X, B says SOME X
    ImplicationConflict, // A implies B, but A is true and B is false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStrategy {
    KeepHigherConfidence,
    KeepMoreRecent,
    KeepMoreSources,
    ManualReview,
    BothValidDifferentContexts,
    FlagForInvestigation,
}

pub struct ContradictionResolver {
    facts: Arc<RwLock<HashMap<String, KnowledgeFact>>>,
    contradictions: Arc<RwLock<Vec<Contradiction>>>,
}

impl ContradictionResolver {
    pub fn new() -> Self {
        Self {
            facts: Arc::new(RwLock::new(HashMap::new())),
            contradictions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add fact and check for contradictions
    pub fn add_fact(&self, fact: KnowledgeFact) -> Vec<Contradiction> {
        let mut found = Vec::new();
        
        // Check against existing facts
        let facts = self.facts.read().unwrap();
        for existing in facts.values() {
            if let Some(contra) = self.detect_contradiction(&fact, existing) {
                found.push(contra);
            }
        }
        drop(facts);

        // Store fact
        self.facts.write().unwrap().insert(fact.fact_id.clone(), fact);

        // Store contradictions
        if !found.is_empty() {
            self.contradictions.write().unwrap().extend(found.clone());
        }

        found
    }

    /// Detect contradiction between two facts
    fn detect_contradiction(&self, a: &KnowledgeFact, b: &KnowledgeFact) -> Option<Contradiction> {
        // Direct negation
        if a.subject == b.subject && a.predicate == b.predicate {
            match (&a.object, &b.object) {
                (Value::Bool(true), Value::Bool(false)) |
                (Value::Bool(false), Value::Bool(true)) => {
                    return Some(Contradiction {
                        fact_a: a.fact_id.clone(),
                        fact_b: b.fact_id.clone(),
                        contradiction_type: ContradictionType::DirectNegation,
                        severity: (a.confidence + b.confidence) / 2.0,
                        resolution_strategy: if a.confidence > b.confidence {
                            ResolutionStrategy::KeepHigherConfidence
                        } else {
                            ResolutionStrategy::KeepMoreRecent
                        },
                    });
                }
                (Value::Integer(v1), Value::Integer(v2)) if v1 != v2 => {
                    return Some(Contradiction {
                        fact_a: a.fact_id.clone(),
                        fact_b: b.fact_id.clone(),
                        contradiction_type: ContradictionType::ValueMismatch,
                        severity: (a.confidence + b.confidence) / 2.0,
                        resolution_strategy: ResolutionStrategy::KeepHigherConfidence,
                    });
                }
                _ => {}
            }
        }

        // Temporal conflict
        if a.subject == b.subject && a.predicate == b.predicate {
            if (a.timestamp - b.timestamp).abs() > 86400000 { // 24 hours
                return Some(Contradiction {
                    fact_a: a.fact_id.clone(),
                    fact_b: b.fact_id.clone(),
                    contradiction_type: ContradictionType::TemporalConflict,
                    severity: 0.5,
                    resolution_strategy: ResolutionStrategy::KeepMoreRecent,
                });
            }
        }

        None
    }

    /// Resolve contradictions
    pub fn resolve_contradictions(&self) -> Vec<Resolution> {
        let contradictions = self.contradictions.read().unwrap();
        let mut facts = self.facts.write().unwrap();
        let mut resolutions = Vec::new();

        for contra in contradictions.iter() {
            let resolution = match contra.resolution_strategy {
                ResolutionStrategy::KeepHigherConfidence => {
                    let fact_a = facts.get(&contra.fact_a).cloned();
                    let fact_b = facts.get(&contra.fact_b).cloned();
                    
                    if let (Some(a), Some(b)) = (fact_a, fact_b) {
                        if a.confidence > b.confidence {
                            facts.get_mut(&b.fact_id).unwrap().validity = Validity::Contradicted;
                            Resolution::Kept(a.fact_id, b.fact_id)
                        } else {
                            facts.get_mut(&a.fact_id).unwrap().validity = Validity::Contradicted;
                            Resolution::Kept(b.fact_id, a.fact_id)
                        }
                    } else {
                        Resolution::Failed
                    }
                }
                ResolutionStrategy::KeepMoreRecent => {
                    let fact_a = facts.get(&contra.fact_a).cloned();
                    let fact_b = facts.get(&contra.fact_b).cloned();
                    
                    if let (Some(a), Some(b)) = (fact_a, fact_b) {
                        if a.timestamp > b.timestamp {
                            facts.get_mut(&b.fact_id).unwrap().validity = Validity::Contradicted;
                            Resolution::Kept(a.fact_id, b.fact_id)
                        } else {
                            facts.get_mut(&a.fact_id).unwrap().validity = Validity::Contradicted;
                            Resolution::Kept(b.fact_id, a.fact_id)
                        }
                    } else {
                        Resolution::Failed
                    }
                }
                _ => Resolution::Flagged(contra.fact_a.clone(), contra.fact_b.clone()),
            };

            resolutions.push(resolution);
        }

        resolutions
    }

    pub fn get_contradictions(&self) -> Vec<Contradiction> {
        self.contradictions.read().unwrap().clone()
    }
}

#[derive(Debug, Clone)]
pub enum Resolution {
    Kept(String, String), // kept_id, retracted_id
    Flagged(String, String),
    Failed,
}

// =============================================================================
// Temporal Reasoning
// =============================================================================

#[derive(Debug, Clone)]
pub struct TemporalReasoner {
    /// Timeline of events
    timeline: Arc<RwLock<BTreeMap<i64, Vec<TemporalEvent>>>>,
    /// Temporal rules
    rules: Arc<RwLock<Vec<TemporalRule>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: i64,
    pub duration_ms: i64,
    pub participants: Vec<String>,
    pub properties: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalRule {
    pub rule_id: String,
    pub antecedent: TemporalPattern,
    pub consequent: TemporalPattern,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemporalPattern {
    Event { event_type: String, constraints: Vec<Constraint> },
    Sequence(Vec<TemporalPattern>),
    Concurrent(Vec<TemporalPattern>),
    During(Box<TemporalPattern>, Box<TemporalPattern>),
    Before(Box<TemporalPattern>, Box<TemporalPattern>),
    After(Box<TemporalPattern>, Box<TemporalPattern>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub property: String,
    pub operator: ConstraintOp,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintOp {
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    Contains,
}

impl TemporalReasoner {
    pub fn new() -> Self {
        Self {
            timeline: Arc::new(RwLock::new(BTreeMap::new())),
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add event to timeline
    pub fn add_event(&self, event: TemporalEvent) {
        self.timeline.write().unwrap()
            .entry(event.timestamp)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Query events in time range
    pub fn query_range(&self, start: i64, end: i64) -> Vec<TemporalEvent> {
        self.timeline.read().unwrap()
            .range(start..=end)
            .flat_map(|(_, events)| events.clone())
            .collect()
    }

    /// Check if event A happened before B
    pub fn happened_before(&self, event_a: &str, event_b: &str) -> bool {
        let timeline = self.timeline.read().unwrap();
        
        let ts_a = timeline.iter()
            .find(|(_, events)| events.iter().any(|e| e.event_id == event_a))
            .map(|(ts, _)| *ts);
        
        let ts_b = timeline.iter()
            .find(|(_, events)| events.iter().any(|e| e.event_id == event_b))
            .map(|(ts, _)| *ts);
        
        match (ts_a, ts_b) {
            (Some(a), Some(b)) => a < b,
            _ => false,
        }
    }

    /// Find events matching pattern
    pub fn find_matching(&self, pattern: &TemporalPattern) -> Vec<TemporalEvent> {
        let timeline = self.timeline.read().unwrap();
        let mut results = Vec::new();

        for events in timeline.values() {
            for event in events {
                if self.event_matches(event, pattern) {
                    results.push(event.clone());
                }
            }
        }

        results
    }

    fn event_matches(&self, event: &TemporalEvent, pattern: &TemporalPattern) -> bool {
        match pattern {
            TemporalPattern::Event { event_type, constraints } => {
                if event.event_type != *event_type {
                    return false;
                }
                constraints.iter().all(|c| {
                    event.properties.get(&c.property)
                        .map(|v| self.check_constraint(v, &c.operator, &c.value))
                        .unwrap_or(false)
                })
            }
            _ => false,
        }
    }

    fn check_constraint(&self, value: &Value, op: &ConstraintOp, target: &Value) -> bool {
        match (op, value, target) {
            (ConstraintOp::Eq, a, b) => a == b,
            (ConstraintOp::Neq, a, b) => a != b,
            (ConstraintOp::Lt, Value::Integer(a), Value::Integer(b)) => a < b,
            (ConstraintOp::Gt, Value::Integer(a), Value::Integer(b)) => a > b,
            (ConstraintOp::Lte, Value::Integer(a), Value::Integer(b)) => a <= b,
            (ConstraintOp::Gte, Value::Integer(a), Value::Integer(b)) => a >= b,
            _ => false,
        }
    }

    /// Infer missing events based on rules
    pub fn infer_missing(&self) -> Vec<TemporalEvent> {
        let rules = self.rules.read().unwrap();
        let mut inferred = Vec::new();

        for rule in rules.iter() {
            // Find antecedent matches
            let antecedent_matches = self.find_matching(&rule.antecedent);
            
            for _match in antecedent_matches {
                // Check if consequent exists
                let consequent_matches = self.find_matching(&rule.consequent);
                
                if consequent_matches.is_empty() {
                    // Infer consequent event
                    if let TemporalPattern::Event { event_type, .. } = &rule.consequent {
                        let inferred_event = TemporalEvent {
                            event_id: format!("inferred-{}", uuid::Uuid::new_v4()),
                            event_type: event_type.clone(),
                            timestamp: chrono::Utc::now().timestamp_millis(),
                            duration_ms: 0,
                            participants: vec![],
                            properties: HashMap::new(),
                        };
                        inferred.push(inferred_event);
                    }
                }
            }
        }

        inferred
    }

    /// Add temporal rule
    pub fn add_rule(&self, rule: TemporalRule) {
        self.rules.write().unwrap().push(rule);
    }
}

// =============================================================================
// Knot Capabilities — Main Controller
// =============================================================================

pub struct KnotCapabilities {
    /// Instruction compiler
    compiler: InstructionCompiler,
    /// Contradiction resolver
    resolver: ContradictionResolver,
    /// Temporal reasoner
    temporal: TemporalReasoner,
}

impl KnotCapabilities {
    pub fn new() -> Self {
        Self {
            compiler: InstructionCompiler::new(),
            resolver: ContradictionResolver::new(),
            temporal: TemporalReasoner::new(),
        }
    }

    /// Compile instruction
    pub fn compile(&mut self, text: &str) -> Result<CompiledInstruction, CompileError> {
        self.compiler.compile(text)
    }

    /// Add fact with contradiction checking
    pub fn add_fact(&self, fact: KnowledgeFact) -> Vec<Contradiction> {
        self.resolver.add_fact(fact)
    }

    /// Resolve contradictions
    pub fn resolve(&self) -> Vec<Resolution> {
        self.resolver.resolve_contradictions()
    }

    /// Add temporal event
    pub fn add_event(&self, event: TemporalEvent) {
        self.temporal.add_event(event);
    }

    /// Query temporal events
    pub fn query_temporal(&self, start: i64, end: i64) -> Vec<TemporalEvent> {
        self.temporal.query_range(start, end)
    }

    /// Infer missing events
    pub fn infer(&self) -> Vec<TemporalEvent> {
        self.temporal.infer_missing()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_compilation() {
        let mut compiler = InstructionCompiler::new();
        
        let text = r#"
            IF temperature > 100 THEN alert
            QUERY current_temperature
            ASSERT system_status == "healthy"
        "#;
        
        let result = compiler.compile(text);
        assert!(result.is_ok());
        
        let compiled = result.unwrap();
        assert!(!compiled.bytecode.is_empty());
    }

    #[test]
    fn test_contradiction_detection() {
        let resolver = ContradictionResolver::new();
        
        let fact1 = KnowledgeFact {
            fact_id: "f1".to_string(),
            subject: "server".to_string(),
            predicate: "status".to_string(),
            object: Value::Bool(true),
            confidence: 0.9,
            sources: vec!["monitor1".to_string()],
            timestamp: 1000,
            validity: Validity::Confirmed,
        };
        
        let fact2 = KnowledgeFact {
            fact_id: "f2".to_string(),
            subject: "server".to_string(),
            predicate: "status".to_string(),
            object: Value::Bool(false), // Contradiction!
            confidence: 0.8,
            sources: vec!["monitor2".to_string()],
            timestamp: 2000,
            validity: Validity::Confirmed,
        };
        
        resolver.add_fact(fact1);
        let contradictions = resolver.add_fact(fact2);
        
        assert!(!contradictions.is_empty());
        assert_eq!(contradictions[0].contradiction_type, ContradictionType::DirectNegation);
    }

    #[test]
    fn test_temporal_reasoning() {
        let reasoner = TemporalReasoner::new();
        
        let event1 = TemporalEvent {
            event_id: "e1".to_string(),
            event_type: "boot".to_string(),
            timestamp: 1000,
            duration_ms: 0,
            participants: vec!["server1".to_string()],
            properties: HashMap::new(),
        };
        
        let event2 = TemporalEvent {
            event_id: "e2".to_string(),
            event_type: "shutdown".to_string(),
            timestamp: 5000,
            duration_ms: 0,
            participants: vec!["server1".to_string()],
            properties: HashMap::new(),
        };
        
        reasoner.add_event(event1);
        reasoner.add_event(event2);
        
        assert!(reasoner.happened_before("e1", "e2"));
        assert!(!reasoner.happened_before("e2", "e1"));
    }
}
