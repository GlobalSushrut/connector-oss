//! # Connector Logic System (CLS)
//!
//! The programmable contract execution layer for the Connector platform.
//! Agents become **contract executors** — behavior is defined declaratively
//! in YAML contracts, compiled into verified IR, and executed by the kernel
//! with full governance, resource budgeting, and receipt chains.
//!
//! ## Architecture
//!
//! ```text
//! contract.yaml → ClsCompiler → SolutionContract → ContractExecutor → ExecutionReceipt
//!                   (compile)      (verified IR)      (kernel exec)     (signed proof)
//! ```
//!
//! ## Key Principles
//!
//! 1. **Agent = contract executor**, not script logic
//! 2. **Contracts are immutable** — change contract → change behavior
//! 3. **Every execution produces a receipt** — verifiable proof chain
//! 4. **Resource budgets are enforced** — tokens, cost, time, tools
//! 5. **Predicates gate everything** — pre/post/invariant conditions
//! 6. **State machines define lifecycle** — no arbitrary state changes
//! 7. **Contracts compose** — call sub-contracts, pipelines, sagas
//!
//! ## Usage
//!
//! ```rust,ignore
//! use connector_engine::cls::{ClsCompiler, ContractExecutor, ContractRegistry};
//! use std::collections::HashMap;
//!
//! // 1. Compile contract from YAML
//! let yaml_str = "..."; // Your contract YAML
//! let contract = ClsCompiler::compile(yaml_str).unwrap();
//!
//! // 2. Register in registry
//! let mut registry = ContractRegistry::new();
//! let cid = registry.register(contract.clone()).unwrap();
//!
//! // 3. Execute with inputs
//! let mut executor = ContractExecutor::stub();
//! let inputs = HashMap::from([("patient_id".into(), serde_json::json!("PAT-001"))]);
//! let receipt = executor.execute(&contract, "agent-1", "session-1", inputs).unwrap();
//!
//! // 4. Receipt contains full audit trail
//! assert_eq!(receipt.outcome, connector_engine::cls::ExecutionOutcome::Success);
//! ```

pub mod types;
pub mod compiler;
pub mod executor;
pub mod registry;
pub mod templates;

// CCL native compiler toolchain
pub mod ccl_lexer;
pub mod ccl_parser;
pub mod ccl_sema;
pub mod ccl_lower;
pub mod ccl_opt;
pub mod ccl_verify;
pub mod ccl_emit;
pub mod connector_ir;

// Re-export primary API
pub use types::{
    SolutionContract, ContractId, ContractVersion, ContractInterface,
    ContractIR, IRNode, CIROp, ContractStateMachine, StateTransition,
    Predicate, Governance, FailureStrategy,
    ResourceEnvelope, ResourceCheck, ResourceViolation,
    ExecutionContext, ExecutionEvent,
    ExecutionReceipt, ExecutionOutcome, NodeResult,
    ParamDef, ParamType,
    ClsError, ClsResult,
};
pub use compiler::{ClsCompiler, SurfaceContract};
pub use executor::{
    ContractExecutor, ToolHandler, LlmHandler, MemoryHandler,
    MessageHandler, ContractHandler, ExecutionStore, InMemoryExecutionStore,
    StubToolHandler, StubLlmHandler, StubMemoryHandler, StubMessageHandler, StubContractHandler,
    CnpMessageHandler, RegistryContractHandler,
};
pub use registry::{ContractRegistry, ContractStatus, ContractEntry};

// Re-export CCL compiler API
pub use ccl_lexer::CclLexer;
pub use ccl_parser::CclParser;
pub use ccl_sema::SemanticAnalyzer;
pub use ccl_lower::IrLowering;
pub use ccl_opt::IrOptimizer;
pub use ccl_verify::IrVerifier;
pub use ccl_emit::{ContractEmitter, compile_ccl, compile_ccl_default, EmitConfig, EmitResult};
pub use connector_ir::connector_ir_from_solution;

// Re-export constitutional block types (per CLS_CONSTITUTIONAL_LOGIC_ARCHITECTURE.md)
pub use ccl_parser::{
    // AST nodes
    ContractNode, BlockNode,
    // Constitutional blocks
    SolutionNode, ImportsNode, ImportDeclNode, ImportKind,
    CapabilitiesNode, CapabilityDeclNode, CapabilityKind, CapabilityModifier,
    PolicyNode, PolicyRuleNode, PolicyRuleKind, PolicyModifier, PolicyModifierKind,
    FlowNode, StageNode, StageOpNode,
    EvidenceNode, EvidenceEntryNode, EvidenceKind,
    OutcomesNode,
    ReviewNode, ReviewTimeoutAction,
    // Original blocks
    IdentityNode, InterfaceNode, StateNode, GovernanceNode, BudgetNode, MemoryNode, BehaviorNode,
    // Supporting types
    InputDeclNode, OutputDeclNode, TypeNode, PrimitiveType,
    StateDefNode, StateKind, TransitionDefNode,
    PredicateNode, CmpOp,
    StepNode, StepOpNode, ParamNode, BranchArmNode, ExprNode,
};
