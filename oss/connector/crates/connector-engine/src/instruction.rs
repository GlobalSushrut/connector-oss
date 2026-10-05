//! Instruction Plane — typed, schema-validated instruction gate.
//!
//! Every instruction entering the system must match a registered schema:
//! `verb(action_kind)(type param.name)` — e.g. `chat.send(str message, str channel)`
//!
//! The InstructionPlane sits between the firewall and the dispatcher:
//! ```text
//! External Input → Firewall (injection) → InstructionPlane (schema) → Dispatcher → Kernel
//! ```
//!
//! If the instruction doesn't match any registered schema → BLOCKED.
//! If the actor isn't registered for that schema → BLOCKED.
//! If parameters don't match types/constraints → BLOCKED.
//! If the source is external and not whitelisted → BLOCKED.
//!
//! Integrates with:
//! - **AAPI Grammar**: each instruction maps to a Kriya `domain.verb`
//! - **VAC Kernel**: validated instructions become SyscallRequests
//! - **Firewall**: injection check happens BEFORE schema validation
//! - **Knowledge**: knowledge queries are instructions too
//! - **Distributed**: schemas are serializable, shareable across nodes

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::action::Param;

// ═══════════════════════════════════════════════════════════════
// Source — where the instruction came from
// ═══════════════════════════════════════════════════════════════

/// Where an instruction originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionSource {
    /// From a registered internal actor (agent PID known)
    Internal { actor_pid: String },
    /// From an external API call (SDK, REST, gRPC)
    External { client_id: String },
    /// From the kernel itself (system-generated)
    System,
}

impl InstructionSource {
    pub fn is_external(&self) -> bool { matches!(self, Self::External { .. }) }
    pub fn is_internal(&self) -> bool { matches!(self, Self::Internal { .. }) }
    pub fn actor_pid(&self) -> Option<&str> {
        match self {
            Self::Internal { actor_pid } => Some(actor_pid),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// InstructionParam — a typed parameter in an instruction
// ═══════════════════════════════════════════════════════════════

/// A parameter definition in an instruction schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionParam {
    /// Parameter name (e.g., "message", "channel")
    pub name: String,
    /// Parameter type
    pub param_type: Param,
    /// Whether this parameter is required
    pub required: bool,
    /// Optional description
    pub description: Option<String>,
}

impl InstructionParam {
    pub fn required(name: &str, param_type: Param) -> Self {
        Self { name: name.to_string(), param_type, required: true, description: None }
    }

    pub fn optional(name: &str, param_type: Param) -> Self {
        Self { name: name.to_string(), param_type, required: false, description: None }
    }

    pub fn with_desc(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }
}

// ═══════════════════════════════════════════════════════════════
// InstructionSchema — the typed signature of an allowed instruction
// ═══════════════════════════════════════════════════════════════

/// Who is allowed to invoke this instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceConstraint {
    /// Only registered internal actors
    RegisteredOnly,
    /// Internal + whitelisted external clients
    AllowExternal { client_ids: Vec<String> },
    /// System-only (no actors can invoke directly)
    SystemOnly,
    /// Any source (dangerous — use only for public read-only queries)
    Any,
}

impl Default for SourceConstraint {
    fn default() -> Self { Self::RegisteredOnly }
}

/// A registered instruction schema — the typed signature of an allowed action.
///
/// Format: `domain.verb(type param, type param, ...)`
/// Example: `chat.send(str message, str channel)` or `memory.write(str content, str namespace)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionSchema {
    /// Kriya-format action: `domain.verb` (e.g., "chat.send", "memory.write")
    pub action: String,
    /// Domain part (e.g., "chat")
    pub domain: String,
    /// Verb part (e.g., "send")
    pub verb: String,
    /// Typed parameter definitions
    pub params: Vec<InstructionParam>,
    /// Roles allowed to invoke this instruction
    pub allowed_roles: Vec<String>,
    /// Source constraint
    pub source_constraint: SourceConstraint,
    /// Whether this instruction is idempotent (safe to retry)
    pub idempotent: bool,
    /// Human-readable description
    pub description: String,
}

impl InstructionSchema {
    /// Create a new schema with `domain.verb` format.
    pub fn new(domain: &str, verb: &str) -> Self {
        Self {
            action: format!("{}.{}", domain, verb),
            domain: domain.to_string(),
            verb: verb.to_string(),
            params: Vec::new(),
            allowed_roles: Vec::new(),
            source_constraint: SourceConstraint::RegisteredOnly,
            idempotent: false,
            description: String::new(),
        }
    }

    pub fn param(mut self, p: InstructionParam) -> Self {
        self.params.push(p);
        self
    }

    pub fn role(mut self, role: &str) -> Self {
        self.allowed_roles.push(role.to_string());
        self
    }

    pub fn roles(mut self, roles: &[&str]) -> Self {
        self.allowed_roles.extend(roles.iter().map(|r| r.to_string()));
        self
    }

    pub fn source(mut self, constraint: SourceConstraint) -> Self {
        self.source_constraint = constraint;
        self
    }

    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    pub fn desc(mut self, d: &str) -> Self {
        self.description = d.to_string();
        self
    }

    /// Get the canonical signature string: `domain.verb(type name, type name, ...)`
    pub fn signature(&self) -> String {
        let params: Vec<String> = self.params.iter().map(|p| {
            let req = if p.required { "" } else { "?" };
            format!("{}{} {}", p.param_type.schema_type(), req, p.name)
        }).collect();
        format!("{}({})", self.action, params.join(", "))
    }
}

// ═══════════════════════════════════════════════════════════════
// Instruction — a concrete instruction to be validated + executed
// ═══════════════════════════════════════════════════════════════

/// A concrete instruction submitted for validation and execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// The action being requested: `domain.verb`
    pub action: String,
    /// Parameters (name → value)
    pub params: HashMap<String, serde_json::Value>,
    /// Who is submitting this instruction
    pub source: InstructionSource,
    /// Actor's role (if known)
    pub role: Option<String>,
    /// Optional Vakya ID linking to AAPI grammar
    pub vakya_id: Option<String>,
}

impl Instruction {
    pub fn new(action: &str, source: InstructionSource) -> Self {
        Self {
            action: action.to_string(),
            params: HashMap::new(),
            source,
            role: None,
            vakya_id: None,
        }
    }

    pub fn with_param(mut self, name: &str, value: serde_json::Value) -> Self {
        self.params.insert(name.to_string(), value);
        self
    }

    pub fn with_role(mut self, role: &str) -> Self {
        self.role = Some(role.to_string());
        self
    }

    pub fn with_vakya(mut self, vakya_id: &str) -> Self {
        self.vakya_id = Some(vakya_id.to_string());
        self
    }
}

// ═══════════════════════════════════════════════════════════════
// ValidationResult — what happened when we validated an instruction
// ═══════════════════════════════════════════════════════════════

/// Why an instruction was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    /// No schema registered for this action
    UnknownAction,
    /// Actor's role is not allowed for this schema
    RoleDenied,
    /// Source type not allowed (e.g., external source on internal-only schema)
    SourceBlocked,
    /// Required parameter missing
    MissingParam { param: String },
    /// Parameter type mismatch
    TypeMismatch { param: String, expected: String, got: String },
    /// Unknown parameter not in schema (strict mode)
    UnknownParam { param: String },
    /// Actor PID not registered in the system
    UnregisteredActor,
}

/// Result of instruction validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the instruction is valid
    pub valid: bool,
    /// The matched schema action (if found)
    pub matched_action: Option<String>,
    /// Rejection reasons (empty if valid)
    pub rejections: Vec<RejectionReason>,
}

impl ValidationResult {
    fn ok(action: &str) -> Self {
        Self { valid: true, matched_action: Some(action.to_string()), rejections: vec![] }
    }
    fn reject(reason: RejectionReason) -> Self {
        Self { valid: false, matched_action: None, rejections: vec![reason] }
    }
    fn reject_with_action(action: &str, reason: RejectionReason) -> Self {
        Self { valid: false, matched_action: Some(action.to_string()), rejections: vec![reason] }
    }
}

// ═══════════════════════════════════════════════════════════════
// InstructionPlane — the registry + validator
// ═══════════════════════════════════════════════════════════════

/// The Instruction Plane — validates every instruction against registered schemas.
///
/// **Default-deny**: if no schema matches, the instruction is BLOCKED.
/// **Actor-bound**: each schema declares which roles can invoke it.
/// **Source-gated**: external sources are blocked unless explicitly whitelisted.
/// **Type-checked**: parameter types are validated against the schema.
///
/// Sits between Firewall and Dispatcher in the execution pipeline.
pub struct InstructionPlane {
    /// Registered schemas keyed by `domain.verb`
    schemas: HashMap<String, InstructionSchema>,
    /// Registered actor PIDs (only these can submit internal instructions)
    registered_actors: HashMap<String, String>, // pid → role
    /// Whether to reject unknown parameters (strict mode)
    strict_params: bool,
    /// Total instructions validated
    total_validated: u64,
    /// Total instructions rejected
    total_rejected: u64,
}

impl InstructionPlane {
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
            registered_actors: HashMap::new(),
            strict_params: true,
            total_validated: 0,
            total_rejected: 0,
        }
    }

    /// Create with strict parameter checking disabled (allows extra params).
    pub fn permissive() -> Self {
        let mut p = Self::new();
        p.strict_params = false;
        p
    }

    /// Register an instruction schema.
    pub fn register_schema(&mut self, schema: InstructionSchema) {
        self.schemas.insert(schema.action.clone(), schema);
    }

    /// Register multiple schemas at once.
    pub fn register_schemas(&mut self, schemas: Vec<InstructionSchema>) {
        for s in schemas { self.register_schema(s); }
    }

    /// Register an actor (agent) as allowed to submit instructions.
    pub fn register_actor(&mut self, pid: &str, role: &str) {
        self.registered_actors.insert(pid.to_string(), role.to_string());
    }

    /// Unregister an actor.
    pub fn unregister_actor(&mut self, pid: &str) {
        self.registered_actors.remove(pid);
    }

    /// Get all registered schema actions.
    pub fn schema_actions(&self) -> Vec<&str> {
        self.schemas.keys().map(|s| s.as_str()).collect()
    }

    /// Get a schema by action name.
    pub fn get_schema(&self, action: &str) -> Option<&InstructionSchema> {
        self.schemas.get(action)
    }

    /// Get schema count.
    pub fn schema_count(&self) -> usize { self.schemas.len() }

    /// Get registered actor count.
    pub fn actor_count(&self) -> usize { self.registered_actors.len() }

    /// Get validation stats.
    pub fn stats(&self) -> (u64, u64) { (self.total_validated, self.total_rejected) }

    /// Validate an instruction against registered schemas.
    ///
    /// This is the core gate — called BEFORE any instruction reaches the dispatcher.
    /// Default-deny: no matching schema = BLOCKED.
    pub fn validate(&mut self, instruction: &Instruction) -> ValidationResult {
        self.total_validated += 1;

        // 1. Find matching schema (default-deny: unknown action = blocked)
        let schema = match self.schemas.get(&instruction.action) {
            Some(s) => s,
            None => {
                self.total_rejected += 1;
                return ValidationResult::reject(RejectionReason::UnknownAction);
            }
        };

        // 2. Source validation
        match &schema.source_constraint {
            SourceConstraint::SystemOnly => {
                if !matches!(instruction.source, InstructionSource::System) {
                    self.total_rejected += 1;
                    return ValidationResult::reject_with_action(
                        &instruction.action, RejectionReason::SourceBlocked,
                    );
                }
            }
            SourceConstraint::RegisteredOnly => {
                if instruction.source.is_external() {
                    self.total_rejected += 1;
                    return ValidationResult::reject_with_action(
                        &instruction.action, RejectionReason::SourceBlocked,
                    );
                }
                // Internal: verify actor is registered
                if let InstructionSource::Internal { actor_pid } = &instruction.source {
                    if !self.registered_actors.contains_key(actor_pid.as_str()) {
                        self.total_rejected += 1;
                        return ValidationResult::reject_with_action(
                            &instruction.action, RejectionReason::UnregisteredActor,
                        );
                    }
                }
            }
            SourceConstraint::AllowExternal { client_ids } => {
                if let InstructionSource::External { client_id } = &instruction.source {
                    if !client_ids.contains(client_id) {
                        self.total_rejected += 1;
                        return ValidationResult::reject_with_action(
                            &instruction.action, RejectionReason::SourceBlocked,
                        );
                    }
                }
                if let InstructionSource::Internal { actor_pid } = &instruction.source {
                    if !self.registered_actors.contains_key(actor_pid.as_str()) {
                        self.total_rejected += 1;
                        return ValidationResult::reject_with_action(
                            &instruction.action, RejectionReason::UnregisteredActor,
                        );
                    }
                }
            }
            SourceConstraint::Any => {} // no restriction
        }

        // 3. Role validation
        if !schema.allowed_roles.is_empty() {
            let actor_role = instruction.role.as_deref()
                .or_else(|| {
                    instruction.source.actor_pid()
                        .and_then(|pid| self.registered_actors.get(pid).map(|r| r.as_str()))
                });

            match actor_role {
                Some(role) if schema.allowed_roles.iter().any(|r| r == role) => {}
                _ => {
                    self.total_rejected += 1;
                    return ValidationResult::reject_with_action(
                        &instruction.action, RejectionReason::RoleDenied,
                    );
                }
            }
        }

        // 4. Required parameter check
        for param_def in &schema.params {
            if param_def.required && !instruction.params.contains_key(&param_def.name) {
                self.total_rejected += 1;
                return ValidationResult::reject_with_action(
                    &instruction.action,
                    RejectionReason::MissingParam { param: param_def.name.clone() },
                );
            }
        }

        // 5. Parameter type validation
        for (name, value) in &instruction.params {
            if let Some(param_def) = schema.params.iter().find(|p| &p.name == name) {
                if !type_matches(&param_def.param_type, value) {
                    self.total_rejected += 1;
                    return ValidationResult::reject_with_action(
                        &instruction.action,
                        RejectionReason::TypeMismatch {
                            param: name.clone(),
                            expected: param_def.param_type.schema_type().to_string(),
                            got: json_type_name(value).to_string(),
                        },
                    );
                }
            } else if self.strict_params {
                // Unknown parameter in strict mode
                self.total_rejected += 1;
                return ValidationResult::reject_with_action(
                    &instruction.action,
                    RejectionReason::UnknownParam { param: name.clone() },
                );
            }
        }

        // All checks passed
        ValidationResult::ok(&instruction.action)
    }

    /// Convenience: validate and return Ok/Err for use in pipelines.
    pub fn gate(&mut self, instruction: &Instruction) -> Result<(), String> {
        let result = self.validate(instruction);
        if result.valid {
            Ok(())
        } else {
            let reasons: Vec<String> = result.rejections.iter().map(|r| format!("{:?}", r)).collect();
            Err(format!("Instruction '{}' blocked: {}", instruction.action, reasons.join(", ")))
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Built-in schema sets — common instruction schemas
    // ═══════════════════════════════════════════════════════════════

    /// Register the standard memory instruction schemas.
    pub fn register_memory_schemas(&mut self) {
        self.register_schemas(vec![
            InstructionSchema::new("memory", "write")
                .param(InstructionParam::required("content", Param::String))
                .param(InstructionParam::required("namespace", Param::String))
                .param(InstructionParam::optional("session_id", Param::String))
                .param(InstructionParam::optional("entities", Param::Array(Box::new(Param::String))))
                .param(InstructionParam::optional("tags", Param::Array(Box::new(Param::String))))
                .roles(&["writer", "admin"])
                .desc("Write a memory packet to a namespace"),
            InstructionSchema::new("memory", "read")
                .param(InstructionParam::required("namespace", Param::String))
                .param(InstructionParam::optional("subject_id", Param::String))
                .param(InstructionParam::optional("limit", Param::Integer))
                .roles(&["reader", "writer", "admin", "auditor"])
                .idempotent()
                .desc("Read memory packets from a namespace"),
            InstructionSchema::new("memory", "seal")
                .param(InstructionParam::required("namespace", Param::String))
                .roles(&["admin"])
                .desc("Seal a memory region (make immutable)"),
        ]);
    }

    /// Register the standard knowledge instruction schemas.
    pub fn register_knowledge_schemas(&mut self) {
        self.register_schemas(vec![
            InstructionSchema::new("knowledge", "query")
                .param(InstructionParam::optional("entities", Param::Array(Box::new(Param::String))))
                .param(InstructionParam::optional("keywords", Param::Array(Box::new(Param::String))))
                .param(InstructionParam::optional("limit", Param::Integer))
                .roles(&["reader", "writer", "admin"])
                .idempotent()
                .desc("Query the knowledge graph"),
            InstructionSchema::new("knowledge", "ingest")
                .param(InstructionParam::required("namespace", Param::String))
                .param(InstructionParam::required("agent_pid", Param::String))
                .roles(&["writer", "admin"])
                .desc("Ingest knowledge from a memory namespace"),
            InstructionSchema::new("knowledge", "seed")
                .param(InstructionParam::required("seed_json", Param::String))
                .roles(&["admin"])
                .source(SourceConstraint::RegisteredOnly)
                .desc("Load pre-trained knowledge seed"),
        ]);
    }

    /// Register the standard chat/interaction instruction schemas.
    pub fn register_chat_schemas(&mut self) {
        self.register_schemas(vec![
            InstructionSchema::new("chat", "send")
                .param(InstructionParam::required("message", Param::String))
                .param(InstructionParam::optional("channel", Param::String))
                .param(InstructionParam::optional("session_id", Param::String))
                .roles(&["writer", "admin"])
                .desc("Send a chat message"),
            InstructionSchema::new("chat", "receive")
                .param(InstructionParam::required("channel", Param::String))
                .param(InstructionParam::optional("limit", Param::Integer))
                .roles(&["reader", "writer", "admin"])
                .idempotent()
                .desc("Receive chat messages from a channel"),
        ]);
    }

    /// Register the standard tool execution instruction schemas.
    pub fn register_tool_schemas(&mut self) {
        self.register_schemas(vec![
            InstructionSchema::new("tool", "call")
                .param(InstructionParam::required("tool_id", Param::String))
                .param(InstructionParam::optional("params", Param::Object))
                .roles(&["writer", "admin", "tool_agent"])
                .desc("Call a registered tool"),
            InstructionSchema::new("tool", "register")
                .param(InstructionParam::required("tool_id", Param::String))
                .param(InstructionParam::required("schema", Param::Object))
                .roles(&["admin"])
                .source(SourceConstraint::RegisteredOnly)
                .desc("Register a new tool definition"),
        ]);
    }

    /// Register ALL standard schemas (memory + knowledge + chat + tool).
    pub fn register_all_standard(&mut self) {
        self.register_memory_schemas();
        self.register_knowledge_schemas();
        self.register_chat_schemas();
        self.register_tool_schemas();
    }
}

impl Default for InstructionPlane {
    fn default() -> Self { Self::new() }
}

// ═══════════════════════════════════════════════════════════════
// Type checking helpers
// ═══════════════════════════════════════════════════════════════

/// Check if a JSON value matches the expected Param type.
fn type_matches(expected: &Param, value: &serde_json::Value) -> bool {
    match expected {
        Param::String => value.is_string(),
        Param::Integer => value.is_i64() || value.is_u64(),
        Param::Float => value.is_f64() || value.is_i64(),
        Param::Boolean => value.is_boolean(),
        Param::Array(_) => value.is_array(),
        Param::Object => value.is_object(),
        Param::Enum(variants) => {
            value.as_str().map(|s| variants.iter().any(|v| v == s)).unwrap_or(false)
        }
        Param::Optional(inner) => value.is_null() || type_matches(inner, value),
        Param::Binary => value.is_string(), // base64-encoded
    }
}

/// Get a human-readable type name for a JSON value.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_plane() -> InstructionPlane {
        let mut plane = InstructionPlane::new();
        plane.register_all_standard();
        plane.register_actor("pid:bot-1", "writer");
        plane.register_actor("pid:admin-1", "admin");
        plane.register_actor("pid:reader-1", "reader");
        plane
    }

    #[test]
    fn test_valid_instruction_passes() {
        let mut plane = setup_plane();

        let instr = Instruction::new("chat.send", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("message", serde_json::json!("hello world"))
            .with_role("writer");

        let result = plane.validate(&instr);
        assert!(result.valid);
        assert_eq!(result.matched_action, Some("chat.send".to_string()));
    }

    #[test]
    fn test_unknown_action_blocked() {
        let mut plane = setup_plane();

        let instr = Instruction::new("hack.inject", InstructionSource::Internal { actor_pid: "pid:bot-1".into() });

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert_eq!(result.rejections, vec![RejectionReason::UnknownAction]);
    }

    #[test]
    fn test_external_source_blocked_on_registered_only() {
        let mut plane = setup_plane();

        // chat.send has SourceConstraint::RegisteredOnly (default)
        let instr = Instruction::new("chat.send", InstructionSource::External { client_id: "unknown-client".into() })
            .with_param("message", serde_json::json!("hello"));

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert_eq!(result.rejections, vec![RejectionReason::SourceBlocked]);
    }

    #[test]
    fn test_unregistered_actor_blocked() {
        let mut plane = setup_plane();

        let instr = Instruction::new("chat.send", InstructionSource::Internal { actor_pid: "pid:unknown".into() })
            .with_param("message", serde_json::json!("hello"))
            .with_role("writer");

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert_eq!(result.rejections, vec![RejectionReason::UnregisteredActor]);
    }

    #[test]
    fn test_role_denied() {
        let mut plane = setup_plane();

        // memory.seal requires "admin" role, reader doesn't have it
        let instr = Instruction::new("memory.seal", InstructionSource::Internal { actor_pid: "pid:reader-1".into() })
            .with_param("namespace", serde_json::json!("ns:test"));

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert_eq!(result.rejections, vec![RejectionReason::RoleDenied]);
    }

    #[test]
    fn test_missing_required_param_blocked() {
        let mut plane = setup_plane();

        // chat.send requires "message" param
        let instr = Instruction::new("chat.send", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_role("writer");
        // no "message" param!

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert!(matches!(result.rejections[0], RejectionReason::MissingParam { .. }));
    }

    #[test]
    fn test_type_mismatch_blocked() {
        let mut plane = setup_plane();

        // chat.send expects "message" as string, but we pass integer
        let instr = Instruction::new("chat.send", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("message", serde_json::json!(42))
            .with_role("writer");

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert!(matches!(result.rejections[0], RejectionReason::TypeMismatch { .. }));
    }

    #[test]
    fn test_unknown_param_blocked_in_strict_mode() {
        let mut plane = setup_plane();

        let instr = Instruction::new("chat.send", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("message", serde_json::json!("hello"))
            .with_param("evil_param", serde_json::json!("injection"))
            .with_role("writer");

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert!(matches!(result.rejections[0], RejectionReason::UnknownParam { .. }));
    }

    #[test]
    fn test_unknown_param_allowed_in_permissive_mode() {
        let mut plane = InstructionPlane::permissive();
        plane.register_all_standard();
        plane.register_actor("pid:bot-1", "writer");

        let instr = Instruction::new("chat.send", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("message", serde_json::json!("hello"))
            .with_param("extra_param", serde_json::json!("allowed"))
            .with_role("writer");

        let result = plane.validate(&instr);
        assert!(result.valid);
    }

    #[test]
    fn test_system_only_schema() {
        let mut plane = InstructionPlane::new();
        plane.register_schema(
            InstructionSchema::new("kernel", "gc")
                .source(SourceConstraint::SystemOnly)
                .desc("Garbage collect — system only")
        );
        plane.register_actor("pid:bot-1", "admin");

        // Internal actor cannot invoke system-only
        let instr = Instruction::new("kernel.gc", InstructionSource::Internal { actor_pid: "pid:bot-1".into() });
        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert_eq!(result.rejections, vec![RejectionReason::SourceBlocked]);

        // System source can invoke
        let instr = Instruction::new("kernel.gc", InstructionSource::System);
        let result = plane.validate(&instr);
        assert!(result.valid);
    }

    #[test]
    fn test_external_whitelisted_client() {
        let mut plane = InstructionPlane::new();
        plane.register_schema(
            InstructionSchema::new("api", "query")
                .param(InstructionParam::required("q", Param::String))
                .source(SourceConstraint::AllowExternal { client_ids: vec!["sdk-client-1".into()] })
                .desc("Public API query")
        );

        // Whitelisted client passes
        let instr = Instruction::new("api.query", InstructionSource::External { client_id: "sdk-client-1".into() })
            .with_param("q", serde_json::json!("search term"));
        let result = plane.validate(&instr);
        assert!(result.valid);

        // Non-whitelisted client blocked
        let instr = Instruction::new("api.query", InstructionSource::External { client_id: "unknown".into() })
            .with_param("q", serde_json::json!("search term"));
        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert_eq!(result.rejections, vec![RejectionReason::SourceBlocked]);
    }

    #[test]
    fn test_gate_convenience_method() {
        let mut plane = setup_plane();

        // Valid instruction
        let instr = Instruction::new("memory.read", InstructionSource::Internal { actor_pid: "pid:reader-1".into() })
            .with_param("namespace", serde_json::json!("ns:test"));
        assert!(plane.gate(&instr).is_ok());

        // Invalid instruction
        let instr = Instruction::new("hack.inject", InstructionSource::Internal { actor_pid: "pid:bot-1".into() });
        assert!(plane.gate(&instr).is_err());
    }

    #[test]
    fn test_schema_signature() {
        let schema = InstructionSchema::new("chat", "send")
            .param(InstructionParam::required("message", Param::String))
            .param(InstructionParam::optional("channel", Param::String));

        assert_eq!(schema.signature(), "chat.send(string message, string? channel)");
    }

    #[test]
    fn test_validation_stats() {
        let mut plane = setup_plane();

        // 2 valid, 1 invalid
        let valid = Instruction::new("chat.send", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("message", serde_json::json!("hi"))
            .with_role("writer");
        plane.validate(&valid);
        plane.validate(&valid);

        let invalid = Instruction::new("hack.inject", InstructionSource::Internal { actor_pid: "pid:bot-1".into() });
        plane.validate(&invalid);

        let (total, rejected) = plane.stats();
        assert_eq!(total, 3);
        assert_eq!(rejected, 1);
    }

    #[test]
    fn test_standard_schemas_registered() {
        let plane = setup_plane();
        assert!(plane.schema_count() >= 10); // memory(3) + knowledge(3) + chat(2) + tool(2)
        assert!(plane.get_schema("memory.write").is_some());
        assert!(plane.get_schema("knowledge.query").is_some());
        assert!(plane.get_schema("chat.send").is_some());
        assert!(plane.get_schema("tool.call").is_some());
    }

    #[test]
    fn test_role_resolved_from_registered_actor() {
        let mut plane = setup_plane();

        // Don't set role on instruction — should resolve from registered actor
        let instr = Instruction::new("memory.write", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("content", serde_json::json!("test"))
            .with_param("namespace", serde_json::json!("ns:test"));
        // pid:bot-1 is registered as "writer", memory.write allows "writer"

        let result = plane.validate(&instr);
        assert!(result.valid);
    }

    #[test]
    fn test_admin_can_seal_memory() {
        let mut plane = setup_plane();

        let instr = Instruction::new("memory.seal", InstructionSource::Internal { actor_pid: "pid:admin-1".into() })
            .with_param("namespace", serde_json::json!("ns:test"));

        let result = plane.validate(&instr);
        assert!(result.valid);
    }

    #[test]
    fn test_array_param_type_check() {
        let mut plane = setup_plane();

        // memory.write has optional "entities" param of type Array(String)
        let instr = Instruction::new("memory.write", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("content", serde_json::json!("test"))
            .with_param("namespace", serde_json::json!("ns:test"))
            .with_param("entities", serde_json::json!(["patient:001", "condition:diabetes"]));

        let result = plane.validate(&instr);
        assert!(result.valid);

        // Pass non-array → should fail
        let instr = Instruction::new("memory.write", InstructionSource::Internal { actor_pid: "pid:bot-1".into() })
            .with_param("content", serde_json::json!("test"))
            .with_param("namespace", serde_json::json!("ns:test"))
            .with_param("entities", serde_json::json!("not-an-array"));

        let result = plane.validate(&instr);
        assert!(!result.valid);
        assert!(matches!(result.rejections[0], RejectionReason::TypeMismatch { .. }));
    }
}
