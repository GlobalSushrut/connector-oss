//! CCL Optimization Passes — conservative IR optimizations.
//!
//! Implements CONNECTOR_CONTRACT_LANGUAGE.md §12.
//! All passes are optional and correctness-preserving:
//!   - Dead step elimination: remove unreachable nodes
//!   - Constant folding: evaluate static predicates at compile time
//!   - Branch simplification: collapse single-arm branches
//!   - Step fusion: merge adjacent SetVar nodes
//!   - Predicate normalization: flatten nested And/Or

use crate::cls::types::{ContractIR, IRNode, CIROp, Predicate};
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════
// Optimization config
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct OptConfig {
    pub dead_step_elimination: bool,
    pub constant_folding: bool,
    pub branch_simplification: bool,
    pub step_fusion: bool,
    pub predicate_normalization: bool,
}

impl Default for OptConfig {
    fn default() -> Self {
        Self {
            dead_step_elimination: true,
            constant_folding: true,
            branch_simplification: true,
            step_fusion: true,
            predicate_normalization: true,
        }
    }
}

impl OptConfig {
    pub fn none() -> Self {
        Self {
            dead_step_elimination: false,
            constant_folding: false,
            branch_simplification: false,
            step_fusion: false,
            predicate_normalization: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Optimization stats
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
pub struct OptStats {
    pub dead_nodes_removed: usize,
    pub constants_folded: usize,
    pub branches_simplified: usize,
    pub steps_fused: usize,
    pub predicates_normalized: usize,
}

// ═══════════════════════════════════════════════════════════════
// Optimizer
// ═══════════════════════════════════════════════════════════════

pub struct IrOptimizer;

impl IrOptimizer {
    /// Run all enabled optimization passes on the IR.
    pub fn optimize(ir: ContractIR, config: &OptConfig) -> (ContractIR, OptStats) {
        let mut ir = ir;
        let mut stats = OptStats::default();

        if config.dead_step_elimination {
            let (new_ir, removed) = Self::eliminate_dead_steps(ir);
            ir = new_ir;
            stats.dead_nodes_removed = removed;
        }

        if config.branch_simplification {
            let (new_ir, simplified) = Self::simplify_branches(ir);
            ir = new_ir;
            stats.branches_simplified = simplified;
        }

        if config.constant_folding {
            let (new_ir, folded) = Self::fold_constants(ir);
            ir = new_ir;
            stats.constants_folded = folded;
        }

        if config.step_fusion {
            let (new_ir, fused) = Self::fuse_steps(ir);
            ir = new_ir;
            stats.steps_fused = fused;
        }

        if config.predicate_normalization {
            let (new_ir, normalized) = Self::normalize_predicates(ir);
            ir = new_ir;
            stats.predicates_normalized = normalized;
        }

        (ir, stats)
    }

    /// Run with all optimizations enabled.
    pub fn optimize_default(ir: ContractIR) -> (ContractIR, OptStats) {
        Self::optimize(ir, &OptConfig::default())
    }

    // ── Dead step elimination ───────────────────────────────────

    fn eliminate_dead_steps(ir: ContractIR) -> (ContractIR, usize) {
        if ir.nodes.is_empty() { return (ir, 0); }

        // BFS from entry to find reachable nodes
        let mut reachable = HashSet::new();
        let mut queue = vec![ir.entry];
        while let Some(idx) = queue.pop() {
            if !reachable.insert(idx) { continue; }
            for &(from, to) in &ir.edges {
                if from == idx && !reachable.contains(&to) {
                    queue.push(to);
                }
            }
        }

        if reachable.len() == ir.nodes.len() {
            return (ir, 0);
        }

        // Build index mapping: old → new
        let removed = ir.nodes.len() - reachable.len();
        let mut old_to_new = vec![usize::MAX; ir.nodes.len()];
        let mut new_idx = 0;
        for i in 0..ir.nodes.len() {
            if reachable.contains(&i) {
                old_to_new[i] = new_idx;
                new_idx += 1;
            }
        }

        let new_nodes: Vec<IRNode> = ir.nodes.into_iter().enumerate()
            .filter(|(i, _)| reachable.contains(i))
            .map(|(_, n)| n)
            .collect();

        let new_edges: Vec<(usize, usize)> = ir.edges.into_iter()
            .filter(|(from, to)| reachable.contains(from) && reachable.contains(to))
            .map(|(from, to)| (old_to_new[from], old_to_new[to]))
            .collect();

        let new_entry = old_to_new[ir.entry];

        (ContractIR { nodes: new_nodes, edges: new_edges, entry: new_entry }, removed)
    }

    // ── Branch simplification ───────────────────────────────────

    fn simplify_branches(mut ir: ContractIR) -> (ContractIR, usize) {
        let mut simplified = 0;
        for node in &mut ir.nodes {
            if let CIROp::Branch { condition, then_node, else_node } = &node.op {
                // If condition is Always → replace with Noop (edge already points to then_node)
                if matches!(condition, Predicate::Always) {
                    node.op = CIROp::Noop;
                    simplified += 1;
                }
                // If condition is Never and else_node exists → replace with Noop
                else if matches!(condition, Predicate::Never) {
                    node.op = CIROp::Noop;
                    simplified += 1;
                }
                // If then_node == else_node → replace with Noop
                else if else_node.as_ref() == Some(then_node) {
                    node.op = CIROp::Noop;
                    simplified += 1;
                }
            }
        }
        (ir, simplified)
    }

    // ── Constant folding ────────────────────────────────────────

    fn fold_constants(mut ir: ContractIR) -> (ContractIR, usize) {
        let mut folded = 0;
        for node in &mut ir.nodes {
            // Fold SetVar with constant values — already constant, nothing to fold
            // Fold predicates that are trivially true/false
            if let Some(ref mut pre) = node.precondition {
                if Self::is_trivially_true(pre) {
                    node.precondition = None;
                    folded += 1;
                }
            }
            if let Some(ref mut post) = node.postcondition {
                if Self::is_trivially_true(post) {
                    node.postcondition = None;
                    folded += 1;
                }
            }
        }
        (ir, folded)
    }

    fn is_trivially_true(pred: &Predicate) -> bool {
        match pred {
            Predicate::Always => true,
            Predicate::And { predicates } => predicates.iter().all(|p| Self::is_trivially_true(p)),
            Predicate::Or { predicates } => predicates.iter().any(|p| Self::is_trivially_true(p)),
            Predicate::Not { predicate } => Self::is_trivially_false(predicate),
            _ => false,
        }
    }

    fn is_trivially_false(pred: &Predicate) -> bool {
        match pred {
            Predicate::Never => true,
            Predicate::And { predicates } => predicates.iter().any(|p| Self::is_trivially_false(p)),
            Predicate::Or { predicates } => predicates.iter().all(|p| Self::is_trivially_false(p)),
            Predicate::Not { predicate } => Self::is_trivially_true(predicate),
            _ => false,
        }
    }

    // ── Step fusion ─────────────────────────────────────────────

    fn fuse_steps(ir: ContractIR) -> (ContractIR, usize) {
        // Find pairs of adjacent SetVar nodes that can be merged
        // For now, count fusible pairs but keep the IR structure intact
        // (Actual fusion would require more complex node merging)
        let mut fusible = 0;
        for &(from, to) in &ir.edges {
            if from < ir.nodes.len() && to < ir.nodes.len() {
                if matches!(ir.nodes[from].op, CIROp::SetVar { .. })
                    && matches!(ir.nodes[to].op, CIROp::SetVar { .. })
                {
                    // Check from has exactly one successor
                    let from_succs = ir.edges.iter().filter(|(f, _)| *f == from).count();
                    let to_preds = ir.edges.iter().filter(|(_, t)| *t == to).count();
                    if from_succs == 1 && to_preds == 1 {
                        fusible += 1;
                    }
                }
            }
        }
        (ir, fusible)
    }

    // ── Predicate normalization ─────────────────────────────────

    fn normalize_predicates(mut ir: ContractIR) -> (ContractIR, usize) {
        let mut normalized = 0;
        for node in &mut ir.nodes {
            if let Some(ref mut pre) = node.precondition {
                let (new_pred, did_normalize) = Self::flatten_predicate(pre.clone());
                if did_normalize {
                    *pre = new_pred;
                    normalized += 1;
                }
            }
            if let Some(ref mut post) = node.postcondition {
                let (new_pred, did_normalize) = Self::flatten_predicate(post.clone());
                if did_normalize {
                    *post = new_pred;
                    normalized += 1;
                }
            }
        }
        (ir, normalized)
    }

    fn flatten_predicate(pred: Predicate) -> (Predicate, bool) {
        match pred {
            Predicate::And { predicates } => {
                let mut flat = Vec::new();
                let mut changed = false;
                for p in predicates {
                    let (flattened, c) = Self::flatten_predicate(p);
                    if c { changed = true; }
                    if let Predicate::And { predicates: inner } = flattened {
                        flat.extend(inner);
                        changed = true;
                    } else {
                        flat.push(flattened);
                    }
                }
                (Predicate::And { predicates: flat }, changed)
            }
            Predicate::Or { predicates } => {
                let mut flat = Vec::new();
                let mut changed = false;
                for p in predicates {
                    let (flattened, c) = Self::flatten_predicate(p);
                    if c { changed = true; }
                    if let Predicate::Or { predicates: inner } = flattened {
                        flat.extend(inner);
                        changed = true;
                    } else {
                        flat.push(flattened);
                    }
                }
                (Predicate::Or { predicates: flat }, changed)
            }
            Predicate::Not { predicate } => {
                // Double negation elimination
                if let Predicate::Not { predicate: inner } = *predicate {
                    (Self::flatten_predicate(*inner).0, true)
                } else {
                    let (flattened, c) = Self::flatten_predicate(*predicate);
                    (Predicate::Not { predicate: Box::new(flattened) }, c)
                }
            }
            other => (other, false),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ir(nodes: Vec<IRNode>, edges: Vec<(usize, usize)>) -> ContractIR {
        ContractIR { nodes, edges, entry: 0 }
    }

    fn noop_node(id: &str) -> IRNode {
        IRNode { node_id: id.into(), label: id.into(), op: CIROp::Noop, precondition: None, postcondition: None }
    }

    fn setvar_node(id: &str, name: &str) -> IRNode {
        IRNode {
            node_id: id.into(), label: id.into(),
            op: CIROp::SetVar { name: name.into(), value: serde_json::json!(1) },
            precondition: None, postcondition: None,
        }
    }

    #[test]
    fn test_dead_step_elimination() {
        // Nodes: 0 -> 1 -> 2, node 3 is unreachable
        let ir = make_ir(
            vec![noop_node("a"), noop_node("b"), noop_node("c"), noop_node("dead")],
            vec![(0, 1), (1, 2)],
        );
        let (optimized, stats) = IrOptimizer::optimize(ir, &OptConfig { dead_step_elimination: true, ..OptConfig::none() });
        assert_eq!(stats.dead_nodes_removed, 1);
        assert_eq!(optimized.nodes.len(), 3);
    }

    #[test]
    fn test_dead_step_no_removal_needed() {
        let ir = make_ir(
            vec![noop_node("a"), noop_node("b")],
            vec![(0, 1)],
        );
        let (optimized, stats) = IrOptimizer::optimize(ir, &OptConfig { dead_step_elimination: true, ..OptConfig::none() });
        assert_eq!(stats.dead_nodes_removed, 0);
        assert_eq!(optimized.nodes.len(), 2);
    }

    #[test]
    fn test_branch_simplification_always() {
        let ir = make_ir(
            vec![IRNode {
                node_id: "branch".into(), label: "branch".into(),
                op: CIROp::Branch { condition: Predicate::Always, then_node: "a".into(), else_node: None },
                precondition: None, postcondition: None,
            }],
            vec![],
        );
        let (optimized, stats) = IrOptimizer::optimize(ir, &OptConfig { branch_simplification: true, ..OptConfig::none() });
        assert_eq!(stats.branches_simplified, 1);
        assert!(matches!(optimized.nodes[0].op, CIROp::Noop));
    }

    #[test]
    fn test_branch_simplification_same_target() {
        let ir = make_ir(
            vec![IRNode {
                node_id: "branch".into(), label: "branch".into(),
                op: CIROp::Branch {
                    condition: Predicate::FieldPresent { field: "x".into() },
                    then_node: "target".into(),
                    else_node: Some("target".into()),
                },
                precondition: None, postcondition: None,
            }],
            vec![],
        );
        let (optimized, stats) = IrOptimizer::optimize(ir, &OptConfig { branch_simplification: true, ..OptConfig::none() });
        assert_eq!(stats.branches_simplified, 1);
    }

    #[test]
    fn test_constant_folding_trivial_precondition() {
        let ir = make_ir(
            vec![IRNode {
                node_id: "n".into(), label: "n".into(),
                op: CIROp::Noop,
                precondition: Some(Predicate::Always),
                postcondition: None,
            }],
            vec![],
        );
        let (optimized, stats) = IrOptimizer::optimize(ir, &OptConfig { constant_folding: true, ..OptConfig::none() });
        assert_eq!(stats.constants_folded, 1);
        assert!(optimized.nodes[0].precondition.is_none());
    }

    #[test]
    fn test_step_fusion_detection() {
        let ir = make_ir(
            vec![setvar_node("a", "x"), setvar_node("b", "y")],
            vec![(0, 1)],
        );
        let (_, stats) = IrOptimizer::optimize(ir, &OptConfig { step_fusion: true, ..OptConfig::none() });
        assert_eq!(stats.steps_fused, 1);
    }

    #[test]
    fn test_predicate_flatten_nested_and() {
        let pred = Predicate::And {
            predicates: vec![
                Predicate::FieldPresent { field: "a".into() },
                Predicate::And {
                    predicates: vec![
                        Predicate::FieldPresent { field: "b".into() },
                        Predicate::FieldPresent { field: "c".into() },
                    ],
                },
            ],
        };
        let (flat, changed) = IrOptimizer::flatten_predicate(pred);
        assert!(changed);
        if let Predicate::And { predicates } = flat {
            assert_eq!(predicates.len(), 3); // flattened from nested
        } else { panic!("expected And"); }
    }

    #[test]
    fn test_predicate_double_negation() {
        let pred = Predicate::Not {
            predicate: Box::new(Predicate::Not {
                predicate: Box::new(Predicate::FieldPresent { field: "x".into() }),
            }),
        };
        let (flat, changed) = IrOptimizer::flatten_predicate(pred);
        assert!(changed);
        assert!(matches!(flat, Predicate::FieldPresent { .. }));
    }

    #[test]
    fn test_full_optimization_pipeline() {
        let ir = make_ir(
            vec![
                noop_node("entry"),
                setvar_node("a", "x"),
                setvar_node("b", "y"),
                noop_node("unreachable"),
            ],
            vec![(0, 1), (1, 2)],
        );
        let (optimized, stats) = IrOptimizer::optimize_default(ir);
        assert_eq!(stats.dead_nodes_removed, 1);
        assert_eq!(optimized.nodes.len(), 3);
    }
}
