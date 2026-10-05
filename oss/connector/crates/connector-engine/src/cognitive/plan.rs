//! # Cognitive Plan Engine
//!
//! Organizes commitments into a DAG of future-state transformations.
//! Plans are NOT flat step lists — they are structured graphs of
//! committed possibilities with temporal ordering and dependency tracking.

use super::types::*;

/// Builds and manages CognitivePlan DAGs from commitments and possibilities.
pub struct PlanEngine;

impl PlanEngine {
    /// Build a cognitive plan from a set of committed possibilities targeting a tension.
    pub fn build(
        goal_tension: &str,
        commitments: &[Commitment],
        possibilities: &[Possibility],
        max_depth: usize,
    ) -> Result<CognitivePlan, String> {
        if commitments.is_empty() {
            return Err("no commitments to plan from".into());
        }

        let now = chrono::Utc::now().timestamp();
        let plan_id = format!("plan:{}:{}", now, goal_tension);

        // Build nodes from committed possibilities
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        for commitment in commitments {
            // Find the possibility this commitment was derived from
            let possibility = possibilities.iter()
                .find(|p| commitment.source_possibilities.contains(&p.id))
                .cloned();

            if let Some(poss) = possibility {
                let node = PlanNode {
                    id: format!("node:{}:{}", plan_id, poss.id),
                    possibility: poss.clone(),
                    commitment_id: Some(commitment.id.clone()),
                    status: PlanNodeStatus::Pending,
                    result: None,
                    evidence_cids: vec![],
                };
                nodes.push(node);
            }
        }

        // Detect dependency edges between nodes
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i == j { continue; }
                // If node j depends on a possibility that node i produces
                let i_id = &nodes[i].possibility.id;
                if nodes[j].possibility.dependencies.contains(i_id) {
                    edges.push(PlanEdge {
                        from: nodes[i].id.clone(),
                        to: nodes[j].id.clone(),
                        edge_type: PlanEdgeType::DependsOn,
                    });
                }
            }
        }

        // If no dependency edges, treat as parallel execution
        if edges.is_empty() && nodes.len() > 1 {
            // Create sequential ordering by commitment strength
            let mut sorted_indices: Vec<usize> = (0..nodes.len()).collect();
            sorted_indices.sort_by(|&a, &b| {
                let sa = commitments.iter()
                    .find(|c| nodes[a].commitment_id.as_deref() == Some(c.id.as_str()))
                    .map(|c| c.strength)
                    .unwrap_or(CommitmentStrength::Hypothetical);
                let sb = commitments.iter()
                    .find(|c| nodes[b].commitment_id.as_deref() == Some(c.id.as_str()))
                    .map(|c| c.strength)
                    .unwrap_or(CommitmentStrength::Hypothetical);
                sb.cmp(&sa)
            });

            // Create sequential edges
            for w in sorted_indices.windows(2) {
                edges.push(PlanEdge {
                    from: nodes[w[0]].id.clone(),
                    to: nodes[w[1]].id.clone(),
                    edge_type: PlanEdgeType::DependsOn,
                });
            }
        }

        // Truncate depth
        if nodes.len() > max_depth {
            nodes.truncate(max_depth);
            let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            edges.retain(|e| node_ids.contains(&e.from) && node_ids.contains(&e.to));
        }

        // Compute initial frontier (nodes with no incoming edges)
        let frontier = Self::compute_frontier(&nodes, &edges);

        // Mark frontier nodes as Ready
        for node in &mut nodes {
            if frontier.contains(&node.id) {
                node.status = PlanNodeStatus::Ready;
            }
        }

        let commitment_id = commitments.first()
            .map(|c| c.id.clone())
            .unwrap_or_default();

        Ok(CognitivePlan {
            id: plan_id,
            goal_tension: goal_tension.to_string(),
            nodes,
            edges,
            current_frontier: frontier,
            commitment_id,
            revision_count: 0,
            created_at: now,
        })
    }

    /// Compute the execution frontier: nodes with no unmet dependencies.
    pub fn compute_frontier(nodes: &[PlanNode], edges: &[PlanEdge]) -> Vec<String> {
        let completed: Vec<&str> = nodes.iter()
            .filter(|n| matches!(n.status, PlanNodeStatus::Completed))
            .map(|n| n.id.as_str())
            .collect();

        nodes.iter()
            .filter(|n| matches!(n.status, PlanNodeStatus::Pending | PlanNodeStatus::Ready))
            .filter(|n| {
                // All incoming DependsOn edges must have completed source
                edges.iter()
                    .filter(|e| e.to == n.id && e.edge_type == PlanEdgeType::DependsOn)
                    .all(|e| completed.contains(&e.from.as_str()))
            })
            .map(|n| n.id.clone())
            .collect()
    }

    /// Advance the plan after a node completes.
    pub fn advance(
        plan: &mut CognitivePlan,
        completed_node: &str,
        result: serde_json::Value,
    ) -> Result<Vec<String>, String> {
        let node = plan.nodes.iter_mut()
            .find(|n| n.id == completed_node)
            .ok_or_else(|| format!("node {} not found in plan", completed_node))?;

        node.status = PlanNodeStatus::Completed;
        node.result = Some(result);

        // Recompute frontier
        plan.current_frontier = Self::compute_frontier(&plan.nodes, &plan.edges);

        // Mark new frontier nodes as Ready
        for node in &mut plan.nodes {
            if plan.current_frontier.contains(&node.id) && node.status == PlanNodeStatus::Pending {
                node.status = PlanNodeStatus::Ready;
            }
        }

        Ok(plan.current_frontier.clone())
    }

    /// Mark a node as failed and activate fallback edges if available.
    pub fn fail_node(
        plan: &mut CognitivePlan,
        failed_node: &str,
        reason: &str,
    ) -> Result<Vec<String>, String> {
        let node = plan.nodes.iter_mut()
            .find(|n| n.id == failed_node)
            .ok_or_else(|| format!("node {} not found in plan", failed_node))?;

        node.status = PlanNodeStatus::Failed { reason: reason.to_string() };

        // Check for fallback edges
        let fallbacks: Vec<String> = plan.edges.iter()
            .filter(|e| e.from == failed_node && e.edge_type == PlanEdgeType::Fallback)
            .map(|e| e.to.clone())
            .collect();

        if !fallbacks.is_empty() {
            // Activate fallback nodes
            for fb in &fallbacks {
                if let Some(n) = plan.nodes.iter_mut().find(|n| n.id == *fb) {
                    n.status = PlanNodeStatus::Ready;
                }
            }
            plan.current_frontier = fallbacks.clone();
            Ok(fallbacks)
        } else {
            // No fallback — recompute frontier excluding failed branches
            plan.current_frontier = Self::compute_frontier(&plan.nodes, &plan.edges);
            Ok(plan.current_frontier.clone())
        }
    }

    /// Check if the plan is complete (all nodes completed or skipped/failed with no active frontier).
    pub fn is_complete(plan: &CognitivePlan) -> bool {
        plan.nodes.iter().all(|n| {
            matches!(n.status,
                PlanNodeStatus::Completed
                | PlanNodeStatus::Failed { .. }
                | PlanNodeStatus::Skipped { .. }
                | PlanNodeStatus::Revised { .. }
            )
        }) || plan.current_frontier.is_empty()
    }

    /// Revise a plan by replacing a node with a new possibility.
    pub fn revise_node(
        plan: &mut CognitivePlan,
        node_id: &str,
        replacement: Possibility,
    ) -> Result<(), String> {
        let node = plan.nodes.iter_mut()
            .find(|n| n.id == node_id)
            .ok_or_else(|| format!("node {} not found", node_id))?;

        let new_id = format!("{}_rev{}", node_id, plan.revision_count + 1);
        node.status = PlanNodeStatus::Revised { replacement: new_id.clone() };

        let new_node = PlanNode {
            id: new_id,
            possibility: replacement,
            commitment_id: None,
            status: PlanNodeStatus::Pending,
            result: None,
            evidence_cids: vec![],
        };
        plan.nodes.push(new_node);
        plan.revision_count += 1;

        // Recompute frontier
        plan.current_frontier = Self::compute_frontier(&plan.nodes, &plan.edges);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commitment(id: &str, poss_id: &str) -> Commitment {
        Commitment {
            id: id.into(),
            commitment_type: CommitmentType::Action { action_id: "act".into() },
            content: "test".into(),
            strength: CommitmentStrength::Working,
            justification: vec![],
            source_possibilities: vec![poss_id.into()],
            source_tensions: vec!["t1".into()],
            revisable: true,
            revision_conditions: vec![],
            created_at: 0,
            expires_at: None,
            status: CommitmentStatus::Active,
            evidence_cids: vec![],
        }
    }

    fn make_possibility(id: &str) -> Possibility {
        Possibility {
            id: id.into(),
            possibility_type: PossibilityType::Act {
                action: "test".into(),
                target: "target".into(),
            },
            description: format!("possibility {}", id),
            preconditions: vec![],
            required_knowledge: vec![],
            expected_value: 0.7,
            risk: 0.2,
            reversibility: Reversibility::FullyReversible,
            dependencies: vec![],
            policy_status: PolicyStatus::Allowed,
            estimated_confidence: 0.8,
            estimated_cost: Cost::default(),
            source_tensions: vec!["t1".into()],
            evaluation: None,
        }
    }

    #[test]
    fn test_build_plan() {
        let commitments = vec![make_commitment("c1", "p1"), make_commitment("c2", "p2")];
        let possibilities = vec![make_possibility("p1"), make_possibility("p2")];
        let plan = PlanEngine::build("t1", &commitments, &possibilities, 10);
        assert!(plan.is_ok());
        let plan = plan.unwrap();
        assert_eq!(plan.nodes.len(), 2);
        assert!(!plan.current_frontier.is_empty());
    }

    #[test]
    fn test_advance_plan() {
        let commitments = vec![make_commitment("c1", "p1")];
        let possibilities = vec![make_possibility("p1")];
        let mut plan = PlanEngine::build("t1", &commitments, &possibilities, 10).unwrap();
        let node_id = plan.nodes[0].id.clone();
        let result = PlanEngine::advance(&mut plan, &node_id, serde_json::json!("done"));
        assert!(result.is_ok());
        assert!(PlanEngine::is_complete(&plan));
    }

    #[test]
    fn test_fail_node() {
        let commitments = vec![make_commitment("c1", "p1")];
        let possibilities = vec![make_possibility("p1")];
        let mut plan = PlanEngine::build("t1", &commitments, &possibilities, 10).unwrap();
        let node_id = plan.nodes[0].id.clone();
        let result = PlanEngine::fail_node(&mut plan, &node_id, "test failure");
        assert!(result.is_ok());
        assert!(matches!(plan.nodes[0].status, PlanNodeStatus::Failed { .. }));
    }
}
