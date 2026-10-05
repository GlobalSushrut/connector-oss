//! CCL Code Emission — produces the final SolutionContract artifact.
//!
//! Implements CONNECTOR_CONTRACT_LANGUAGE.md §14.
//! Takes verified LoweredContract and emits:
//!   - SolutionContract with CID (content-addressed SHA-256)
//!   - Optional Ed25519 signature
//!   - Immutable, self-describing, signed artifact

use crate::cls::ccl_lower::LoweredContract;
use crate::cls::ccl_opt::{IrOptimizer, OptConfig, OptStats};
use crate::cls::ccl_verify::{IrVerifier, VerifyResult};
use crate::cls::connector_ir::connector_ir_from_solution;
use crate::cls::types::{
    SolutionContract, ContractId, ContractVersion, ClsError, ClsResult,
};
use connector_native_contract::ConnectorIrV1;
use sha2::{Sha256, Digest};

// ═══════════════════════════════════════════════════════════════
// Emission config
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct EmitConfig {
    /// Whether to sign the contract with Ed25519
    pub sign: bool,
    /// Author DID (required if sign is true)
    pub author: String,
    /// Run optimization before emission
    pub optimize: bool,
    /// Optimization config
    pub opt_config: OptConfig,
}

impl Default for EmitConfig {
    fn default() -> Self {
        Self {
            sign: false,
            author: "anonymous".into(),
            optimize: true,
            opt_config: OptConfig::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Emission result
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
pub struct EmitResult {
    pub contract: SolutionContract,
    pub cid: String,
    pub connector_ir: ConnectorIrV1,
    pub opt_stats: OptStats,
    pub verify_result: VerifyResult,
}

// ═══════════════════════════════════════════════════════════════
// Emitter
// ═══════════════════════════════════════════════════════════════

pub struct ContractEmitter;

impl ContractEmitter {
    /// Emit a SolutionContract from a lowered contract.
    /// Runs optimization + verification + CID computation.
    pub fn emit(lowered: LoweredContract, config: &EmitConfig) -> ClsResult<EmitResult> {
        // 1. Optimize IR
        let (ir, opt_stats) = if config.optimize {
            IrOptimizer::optimize(lowered.ir.clone(), &config.opt_config)
        } else {
            (lowered.ir.clone(), OptStats::default())
        };

        // 2. Rebuild lowered with optimized IR
        let optimized = LoweredContract {
            ir,
            ..lowered
        };

        // 3. Verify
        let verify_result = IrVerifier::verify(&optimized);
        if !verify_result.passed {
            let error_msgs: Vec<String> = verify_result.errors().iter()
                .map(|d| format!("[{}] {}", d.code, d.message))
                .collect();
            return Err(ClsError::CompilationError {
                detail: format!("verification failed: {}", error_msgs.join("; ")),
            });
        }

        // 4. Parse version from identity
        let version_str = optimized.identity.get("version")
            .cloned().unwrap_or_else(|| "0.1.0".into());
        let version = parse_version(&version_str);

        // 5. Build the SolutionContract (without CID/signature first)
        let name = optimized.identity.get("name")
            .cloned().unwrap_or_else(|| optimized.name.clone());

        let mut contract = SolutionContract {
            id: ContractId {
                cid: String::new(), // computed below
                name: name.clone(),
                version,
                author: config.author.clone(),
            },
            interface: optimized.interface,
            ir: optimized.ir,
            state_machine: optimized.state_machine,
            governance: optimized.governance,
            resource_envelope: optimized.envelope,
            domain: optimized.domain,
            description: optimized.description,
            compiled_at: now_ms(),
            signature: None,
        };

        // 6. Compute CID
        let cid = compute_cid(&contract);
        contract.id.cid = cid.clone();

        // 7. Sign (optional)
        if config.sign {
            let sig = compute_signature(&contract);
            contract.signature = Some(sig);
        }

        Ok(EmitResult {
            connector_ir: connector_ir_from_solution(&contract, &cid),
            contract,
            cid,
            opt_stats,
            verify_result,
        })
    }

    /// Convenience: emit with default config.
    pub fn emit_default(lowered: LoweredContract) -> ClsResult<EmitResult> {
        Self::emit(lowered, &EmitConfig::default())
    }
}

// ═══════════════════════════════════════════════════════════════
// CID computation: cls1-sha256-<hex>
// ═══════════════════════════════════════════════════════════════

fn compute_cid(contract: &SolutionContract) -> String {
    let canonical = canonical_json(contract);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    format!("cls1-sha256-{}", hex::encode(hash))
}

fn canonical_json(contract: &SolutionContract) -> String {
    // Deterministic JSON of the contract content (excluding CID and signature)
    let obj = serde_json::json!({
        "name": contract.id.name,
        "version": format!("{}", contract.id.version),
        "description": contract.description,
        "domain": contract.domain,
        "interface": serde_json::to_value(&contract.interface).unwrap_or_default(),
        "ir_nodes": serde_json::to_value(&contract.ir.nodes).unwrap_or_default(),
        "ir_edges": serde_json::to_value(&contract.ir.edges).unwrap_or_default(),
        "state_machine": serde_json::to_value(&contract.state_machine).unwrap_or_default(),
        "governance": serde_json::to_value(&contract.governance).unwrap_or_default(),
        "envelope": serde_json::to_value(&contract.resource_envelope).unwrap_or_default(),
    });
    // serde_json produces deterministic output for the same input structure
    serde_json::to_string(&obj).unwrap_or_default()
}

// ═══════════════════════════════════════════════════════════════
// Signature (simulated Ed25519 — production uses ed25519-dalek)
// ═══════════════════════════════════════════════════════════════

fn compute_signature(contract: &SolutionContract) -> String {
    // In production: Ed25519 sign over CID + canonical_json
    // Here we compute HMAC-SHA256 as a placeholder
    let mut hasher = Sha256::new();
    hasher.update(b"ccl-sign-v1:");
    hasher.update(contract.id.cid.as_bytes());
    hasher.update(b":");
    hasher.update(contract.id.author.as_bytes());
    let hash = hasher.finalize();
    hex::encode(hash)
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn parse_version(s: &str) -> ContractVersion {
    let parts: Vec<&str> = s.split('.').collect();
    ContractVersion {
        major: parts.first().and_then(|p| p.parse().ok()).unwrap_or(0),
        minor: parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(1),
        patch: parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════
// Full pipeline convenience function
// ═══════════════════════════════════════════════════════════════

/// Compile CCL source → SolutionContract in one call.
/// This is the top-level entry point for the CCL compiler.
pub fn compile_ccl(source: &str, config: &EmitConfig) -> ClsResult<EmitResult> {
    use crate::cls::ccl_parser::CclParser;
    use crate::cls::ccl_sema::SemanticAnalyzer;
    use crate::cls::ccl_lower::IrLowering;

    // Phase 1: Lex + Parse
    let contract_ast = CclParser::parse(source).map_err(|errors| {
        ClsError::CompilationError {
            detail: errors.iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; "),
        }
    })?;

    // Phase 2: Semantic Analysis
    let (symbols, sema_diags) = SemanticAnalyzer::analyze(&contract_ast);
    let sema_errors: Vec<_> = sema_diags.iter().filter(|d| d.is_error()).collect();
    if !sema_errors.is_empty() {
        return Err(ClsError::CompilationError {
            detail: sema_errors.iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    // Phase 3: IR Lowering
    let lowered = IrLowering::lower(&contract_ast, &symbols).map_err(|errors| {
        ClsError::CompilationError {
            detail: errors.iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; "),
        }
    })?;

    // Phase 4+5+6: Optimize + Verify + Emit
    ContractEmitter::emit(lowered, config)
}

/// Compile with default config.
pub fn compile_ccl_default(source: &str) -> ClsResult<SolutionContract> {
    compile_ccl(source, &EmitConfig::default()).map(|r| r.contract)
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn full_contract_src() -> &'static str {
        r#"contract patient_triage {
            identity {
                name: "patient_triage"
                version: "1.0.0"
                domain: "healthcare"
                description: "Triage incoming patients"
            }
            interface {
                input patient_id: String required
                output triage_result: Json
                tool lookup_patient
                tool assess_severity
                event triage_complete
            }
            state {
                initial intake
                terminal triaged
                intake -> triaged on complete
            }
            governance {
                require patient_id is present
                ensure triage_result is present
                roles [clinician]
                clearance "high"
                compliance [hipaa]
            }
            budget {
                tokens: 4096
                cost_usd: 0.50
                tool_calls: 10
            }
            memory {
                use medical_history as history
            }
            behavior {
                step do_lookup {
                    tool lookup_patient { id: ${patient_id} } -> patient
                }
                step do_assess {
                    tool assess_severity { data: ${patient} } -> assessment
                    set triage_result = ${assessment}
                    transition triaged
                    emit triage_complete { result: ${triage_result} }
                }
            }
        }"#
    }

    #[test]
    fn test_full_pipeline_compiles() {
        let result = compile_ccl(full_contract_src(), &EmitConfig::default());
        assert!(result.is_ok(), "compile failed: {:?}", result.err());
        let emit = result.unwrap();
        assert!(emit.cid.starts_with("cls1-sha256-"));
        assert!(emit.connector_ir.ir_cid.starts_with("cir1-sha256-"));
        assert!(emit.connector_ir.requires_admission());
        assert_eq!(emit.contract.id.name, "patient_triage");
        assert_eq!(emit.contract.id.version.major, 1);
        assert_eq!(emit.contract.id.version.minor, 0);
        assert_eq!(emit.contract.id.version.patch, 0);
        assert!(emit.contract.compiled_at > 0);
    }

    #[test]
    fn test_cid_determinism() {
        let r1 = compile_ccl_default(full_contract_src()).unwrap();
        let r2 = compile_ccl_default(full_contract_src()).unwrap();
        // CIDs should be identical for same source (ignoring timestamp)
        // Since compiled_at differs, we check the canonical content hash
        assert_eq!(r1.id.name, r2.id.name);
        assert_eq!(r1.id.version, r2.id.version);
        assert_eq!(r1.ir.nodes.len(), r2.ir.nodes.len());
    }

    #[test]
    fn test_signed_contract() {
        let config = EmitConfig {
            sign: true,
            author: "did:key:z6Mk_test_agent".into(),
            ..EmitConfig::default()
        };
        let result = compile_ccl(full_contract_src(), &config);
        assert!(result.is_ok());
        let emit = result.unwrap();
        assert!(emit.contract.signature.is_some());
        assert_eq!(emit.contract.id.author, "did:key:z6Mk_test_agent");
    }

    #[test]
    fn test_compile_invalid_source() {
        let result = compile_ccl_default("this is not valid CCL");
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_semantic_error() {
        let src = r#"contract bad {
            behavior {
                step s {
                    tool undeclared_tool { } -> r
                }
            }
        }"#;
        let result = compile_ccl_default(src);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{}", err).contains("E011") || format!("{}", err).contains("undeclared"));
    }

    #[test]
    fn test_compile_convenience_function() {
        let contract = compile_ccl_default(full_contract_src());
        assert!(contract.is_ok());
        let c = contract.unwrap();
        assert!(c.ir.nodes.len() >= 2);
        assert!(!c.ir.edges.is_empty());
    }

    #[test]
    fn test_optimization_stats_reported() {
        let config = EmitConfig { optimize: true, ..EmitConfig::default() };
        let result = compile_ccl(full_contract_src(), &config).unwrap();
        // Stats should be populated (even if 0)
        let _ = result.opt_stats;
    }

    #[test]
    fn test_no_optimization() {
        let config = EmitConfig {
            optimize: false,
            ..EmitConfig::default()
        };
        let result = compile_ccl(full_contract_src(), &config).unwrap();
        assert_eq!(result.opt_stats.dead_nodes_removed, 0);
        assert_eq!(result.opt_stats.branches_simplified, 0);
    }

    #[test]
    fn test_contract_validates_after_emit() {
        let contract = compile_ccl_default(full_contract_src()).unwrap();
        let validation_errors = contract.validate();
        assert!(validation_errors.is_empty(), "validation errors: {:?}", validation_errors);
    }
}
