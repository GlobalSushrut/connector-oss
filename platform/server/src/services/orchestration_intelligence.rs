//! **Orchestration Intelligence v1** — k8s-style control-plane scheduling over **light intelligence leaves**.
//!
//! ## Two layers (not node-path orchestration)
//!
//! | Layer | k8s analog | Connector analog | Weight |
//! |-------|------------|------------------|--------|
//! | **Control plane** | API server schedules Pods into waves | Wave planner, admission, concurrency cap, circuit breakers | Light scheduler — no LLM |
//! | **Intelligence leaves** | Container runs workload | Agent identity + one LLM call per leaf | Light reasoning — not a workflow engine |
//!
//! Clustering in Connector is **intelligence-identity × placement** (DNS/geo/hardware), not
//! "different nodes" as the product unit. This module schedules **waves of intelligences** on one
//! substrate node; `/infra/orchestrator` is a separate heavy DAG planner and does **not** execute
//! agent LLM chains.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "orchestration_intelligence.v1";

/// Max concurrent LLM branches per parallel wave (fail-safe cap).
pub fn parallel_max_agents() -> usize {
    std::env::var("CONNECTOR_PARALLEL_INTEL_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(8)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceStandard {
    pub schema: String,
    pub principle: String,
    pub placement_model: String,
    pub layers: OrchestrationLayers,
    pub execution: IntelligenceExecution,
    pub intelligence_chain: IntelligenceChainDoc,
    pub merge_strategies: Vec<MergeStrategyDoc>,
    pub not_this: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationLayers {
    pub control_plane: String,
    pub intelligence_leaves: String,
    pub separation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceChainDoc {
    pub model: String,
    pub rule: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceExecution {
    pub model: String,
    pub parallel: String,
    pub sequential_between_waves: String,
    pub admission: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeStrategyDoc {
    pub id: String,
    pub description: String,
}

/// One link in the intelligence chain: wave output becomes next wave input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceChainLink {
    pub wave: u32,
    pub kind: String,
    pub agents: Vec<String>,
    pub merge: Option<String>,
    pub input_fingerprint: String,
    pub input_preview: String,
    pub output_fingerprint: String,
    pub output_preview: String,
    pub chained_from: Option<u32>,
}

pub fn chain_preview(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

pub fn chain_fingerprint(text: &str) -> String {
    let hash = Sha256::digest(text.as_bytes());
    format!("sha256:{}", hex::encode(&hash[..8]))
}

/// Record a completed wave in the intelligence chain (output feeds wave N+1).
pub fn record_chain_link(
    wave: u32,
    kind: &str,
    agents: &[String],
    merge: Option<&str>,
    input: &str,
    output: &str,
) -> IntelligenceChainLink {
    IntelligenceChainLink {
        wave,
        kind: kind.into(),
        agents: agents.to_vec(),
        merge: merge.map(str::to_string),
        input_fingerprint: chain_fingerprint(input),
        input_preview: chain_preview(input, 160),
        output_fingerprint: chain_fingerprint(output),
        output_preview: chain_preview(output, 160),
        chained_from: if wave > 0 { Some(wave - 1) } else { None },
    }
}

pub fn intelligence_standard_json() -> serde_json::Value {
    let s = IntelligenceStandard {
        schema: SCHEMA.into(),
        principle: "Control plane schedules intelligence waves; leaves run light LLM reasoning. Chain = wave output → next wave input — not a heavy node-path workflow engine.".into(),
        placement_model: "Intelligence identities over hardware/DNS/geo — not kubernetes-as-product scale-out (see FINAL_OUTCOME §7).".into(),
        layers: OrchestrationLayers {
            control_plane: "Wave planner + admission + concurrency cap + circuit breakers — k8s-scheduler analog, no LLM".into(),
            intelligence_leaves: "Per-agent register + one LLM dispatch + merge — lightweight reasoning unit, not /infra/orchestrator DAG".into(),
            separation: "POST /multiagent/pipeline = intelligence chaining; POST /infra/orchestrator/submit = heavy DAG planner only".into(),
        },
        execution: IntelligenceExecution {
            model: "wave".into(),
            parallel: "Same-wave agents share input; tokio::join_all (real parallelism)".into(),
            sequential_between_waves: "Wave N merged output chains to wave N+1 input (intelligence_chain in response)".into(),
            admission: "Per-leaf pipeline_step + llm_chat before each LLM dispatch".into(),
        },
        intelligence_chain: IntelligenceChainDoc {
            model: "linked_waves".into(),
            rule: "Each wave records input/output fingerprint + preview; chained_from links wave N to N-1".into(),
            fields: vec![
                "wave".into(),
                "kind".into(),
                "agents".into(),
                "input_fingerprint".into(),
                "output_fingerprint".into(),
                "chained_from".into(),
            ],
        },
        merge_strategies: vec![
            MergeStrategyDoc { id: "diverse".into(), description: "Label each branch perspective; default for parallel groups".into() },
            MergeStrategyDoc { id: "concat".into(), description: "Join outputs with blank line separator".into() },
            MergeStrategyDoc { id: "rank".into(), description: "Pick branch with best diversity score (length minus overlap penalty)".into() },
            MergeStrategyDoc { id: "consensus".into(), description: "Exact-match mode across branches; else rank fallback".into() },
            MergeStrategyDoc { id: "longest".into(), description: "Longest substantive output (alias: best_score)".into() },
        ],
        not_this: vec![
            "Kubernetes node-path clustering as the orchestration unit".into(),
            "Multi-node BFT execution of pipeline waves (in-process only today)".into(),
            "/infra/orchestrator DAG advance executing agent LLM chains".into(),
            "Fake sequential parallel_group with merge labels only".into(),
        ],
    };
    serde_json::to_value(s).unwrap_or(json!({ "schema": SCHEMA }))
}

/// One execution unit: single agent or a parallel intelligence wave.
#[derive(Debug, Clone)]
pub enum PipelineWave {
    Single {
        index: usize,
    },
    Parallel {
        group: String,
        indices: Vec<usize>,
        merge: String,
    },
}

/// Plan ordered waves from parallel_group tags (one tag per agent index).
pub fn plan_waves(
    parallel_groups: &[Option<String>],
    merge_strategies: &[Option<String>],
) -> Vec<PipelineWave> {
    let mut waves = Vec::new();
    let mut i = 0;
    while i < parallel_groups.len() {
        if let Some(ref group) = parallel_groups[i] {
            let merge = merge_strategies
                .get(i)
                .and_then(|m| m.clone())
                .unwrap_or_else(|| "diverse".into());
            let mut indices = vec![i];
            i += 1;
            while i < parallel_groups.len() && parallel_groups[i].as_deref() == Some(group.as_str())
            {
                indices.push(i);
                i += 1;
            }
            waves.push(PipelineWave::Parallel {
                group: group.clone(),
                indices,
                merge,
            });
        } else {
            waves.push(PipelineWave::Single { index: i });
            i += 1;
        }
    }
    waves
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn word_set(s: &str) -> std::collections::HashSet<String> {
    s.to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(str::to_string)
        .collect()
}

fn overlap_penalty(a: &str, b: &str) -> usize {
    let wa = word_set(a);
    let wb = word_set(b);
    if wa.is_empty() || wb.is_empty() {
        return 0;
    }
    let inter = wa.intersection(&wb).count();
    inter * 8
}

fn diversity_score(output: &str, others: &[&str]) -> isize {
    let len = output.len() as isize;
    let penalty: isize = others
        .iter()
        .map(|o| overlap_penalty(output, o) as isize)
        .sum();
    len - penalty
}

/// Merge parallel branch outputs into one string for the next wave.
pub fn merge_parallel_outputs(
    branches: &[(String, String)], // (agent_name, output)
    strategy: &str,
) -> String {
    if branches.is_empty() {
        return String::new();
    }
    if branches.len() == 1 {
        return branches[0].1.clone();
    }
    let strat = strategy.trim().to_ascii_lowercase();
    let strat = match strat.as_str() {
        "best_score" => "longest",
        "summarize" => "diverse",
        s => s,
    };

    match strat {
        "longest" => branches
            .iter()
            .max_by_key(|(_, t)| t.len())
            .map(|(_, t)| t.clone())
            .unwrap_or_default(),
        "consensus" => {
            let normalized: Vec<String> = branches.iter().map(|(_, t)| normalize_ws(t)).collect();
            let mut counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for n in &normalized {
                *counts.entry(n.as_str()).or_insert(0) += 1;
            }
            if let Some((winner, &count)) = counts.iter().max_by_key(|(_, c)| *c) {
                if count > 1 {
                    return (*winner).to_string();
                }
            }
            rank_merge(branches)
        }
        "rank" => rank_merge(branches),
        "concat" => branches
            .iter()
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n\n"),
        _ => branches
            .iter()
            .map(|(name, text)| format!("## {name}\n{text}"))
            .collect::<Vec<_>>()
            .join("\n\n"),
    }
}

fn rank_merge(branches: &[(String, String)]) -> String {
    let texts: Vec<&str> = branches.iter().map(|(_, t)| t.as_str()).collect();
    let mut best_idx = 0usize;
    let mut best_score = isize::MIN;
    for (i, (_, text)) in branches.iter().enumerate() {
        let others: Vec<&str> = texts
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, t)| *t)
            .collect();
        let score = diversity_score(text, &others);
        if score > best_score {
            best_score = score;
            best_idx = i;
        }
    }
    branches[best_idx].1.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_waves_groups_adjacent_parallel_agents() {
        let groups = vec![None, Some("critics".into()), Some("critics".into()), None];
        let merges = vec![None, None, None, None];
        let waves = plan_waves(&groups, &merges);
        assert_eq!(waves.len(), 3);
        match &waves[1] {
            PipelineWave::Parallel { indices, group, .. } => {
                assert_eq!(group, "critics");
                assert_eq!(indices, &vec![1, 2]);
            }
            _ => panic!("expected parallel wave"),
        }
    }

    #[test]
    fn merge_diverse_labels_branches() {
        let branches = vec![
            ("optimist".into(), "good".into()),
            ("skeptic".into(), "risky".into()),
        ];
        let m = merge_parallel_outputs(&branches, "diverse");
        assert!(m.contains("## optimist"));
        assert!(m.contains("## skeptic"));
    }

    #[test]
    fn merge_consensus_picks_mode() {
        let branches = vec![
            ("a".into(), "same answer".into()),
            ("b".into(), "same answer".into()),
            ("c".into(), "different".into()),
        ];
        let m = merge_parallel_outputs(&branches, "consensus");
        assert_eq!(m, "same answer");
    }

    #[test]
    fn parallel_max_default() {
        assert!(parallel_max_agents() >= 1);
    }

    #[test]
    fn chain_fingerprint_stable() {
        let a = chain_fingerprint("hello");
        let b = chain_fingerprint("hello");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn record_chain_link_links_waves() {
        let link = record_chain_link(
            1,
            "parallel",
            &["a".into(), "b".into()],
            Some("diverse"),
            "input text",
            "output text",
        );
        assert_eq!(link.chained_from, Some(0));
        assert_eq!(link.kind, "parallel");
        assert_ne!(link.input_fingerprint, link.output_fingerprint);
    }

    #[test]
    fn standard_json_has_layers_and_not_this() {
        let v = intelligence_standard_json();
        assert!(v.get("layers").is_some());
        assert!(v.get("placement_model").is_some());
        assert!(
            v.get("not_this")
                .and_then(|n| n.as_array())
                .map(|a| !a.is_empty())
                == Some(true)
        );
    }
}
