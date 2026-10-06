//! Fleet action chain. Eleven logic verbs, one robustness number.
//!
//! The number is signal-temporal-logic robustness (Maler & Nickovic; Fainekos & Pappas).
//! A step is admitted only when the next robustness is nonnegative, which is the
//! control-barrier inequality for α(h) = h (Ames, Xu, Grizzle, Tabuada).
//! A repeated address with the same range digest is a cycle on the grant graph.
//! This module does not return Allow, Ask, or Block.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;
use crate::substrate::cvr::runtime_adapter::{POLICY_GEN_FOLDER, PROJECTION_SCHEMA};

pub const VERB_COUNT: usize = 11;
pub const LOGIC_VERBS: [&str; VERB_COUNT] = [
    "locate", "grant", "bind", "range", "sequence", "measure", "slack", "cover", "cycle",
    "project", "cease",
];
pub const CHARTER_SCHEMA: &str = "connector.fleet_action_chain.v1";
pub const DNA_SCHEMA: &str = "connector.fleet_action_sequence_dna.v1";
pub const CHARTER_FOLDER: &str = "fleet_chain_charter_v1";
pub const WALK_FOLDER: &str = "fleet_chain_walk_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicVerb {
    Locate,
    Grant,
    Bind,
    Range,
    Sequence,
    Measure,
    Slack,
    Cover,
    Cycle,
    Project,
    Cease,
}

pub fn parse_verb(name: &str) -> Result<LogicVerb, &'static str> {
    match name.trim() {
        "locate" => Ok(LogicVerb::Locate),
        "grant" => Ok(LogicVerb::Grant),
        "bind" => Ok(LogicVerb::Bind),
        "range" => Ok(LogicVerb::Range),
        "sequence" => Ok(LogicVerb::Sequence),
        "measure" => Ok(LogicVerb::Measure),
        "slack" => Ok(LogicVerb::Slack),
        "cover" => Ok(LogicVerb::Cover),
        "cycle" => Ok(LogicVerb::Cycle),
        "project" => Ok(LogicVerb::Project),
        "cease" => Ok(LogicVerb::Cease),
        _ => Err("twelfth_verb_rejected"),
    }
}

/// Closed interval. Derived intervals are widened with one ulp so the result
/// still contains the true range (IEEE 1788 outward rounding on a correctly
/// rounded f64 sum).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Interval {
    pub lo: f64,
    pub hi: f64,
}

impl Interval {
    pub fn add(self, rhs: Self) -> Self {
        Interval {
            lo: (self.lo + rhs.lo).next_down(),
            hi: (self.hi + rhs.hi).next_up(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleRow {
    pub id: String,
    pub intervals: Vec<(f64, f64)>,
    pub controllable: Vec<bool>,
}

#[derive(Debug, Clone)]
pub struct WalkMemory {
    pub committed: Vec<CommittedStep>,
    pub prev_digest: String,
}

#[derive(Debug, Clone)]
pub struct CommittedStep {
    pub address: String,
    pub range_digest: String,
    pub sequence_digest: String,
    pub robustness: f64,
    pub effect_taken: bool,
}

#[derive(Debug, Clone)]
pub struct DecideInput<'a> {
    pub agent: &'a str,
    pub address: &'a str,
    pub address_type: &'a str,
    pub task: &'a str,
    pub y: &'a [f64],
    pub proposed_y: Option<&'a [f64]>,
    pub rows: &'a [RuleRow],
    pub grant_edge: bool,
    pub sealed: bool,
    pub walk: &'a WalkMemory,
}

/// Atomic robustness of `y ∈ [r1, r2]`: min(y − r1, r2 − y).
pub fn atomic_slack(y: f64, r1: f64, r2: f64) -> f64 {
    if !y.is_finite() || !r1.is_finite() || !r2.is_finite() || r2 < r1 {
        return f64::NEG_INFINITY;
    }
    (y - r1).min(r2 - y)
}

/// A row is a conjunction, so robustness is the minimum across axes.
pub fn row_robustness(y: &[f64], intervals: &[(f64, f64)]) -> f64 {
    if y.is_empty() || y.len() != intervals.len() {
        return f64::NEG_INFINITY;
    }
    let mut slack = f64::INFINITY;
    for (yi, (r1, r2)) in y.iter().zip(intervals.iter()) {
        slack = slack.min(atomic_slack(*yi, *r1, *r2));
    }
    slack
}

/// The union of rules is a disjunction, so robustness is the maximum across rows.
pub fn union_robustness(y: &[f64], rows: &[RuleRow]) -> (f64, Option<usize>) {
    let mut best = f64::NEG_INFINITY;
    let mut at = None;
    for (i, row) in rows.iter().enumerate() {
        let h = row_robustness(y, &row.intervals);
        if h > best {
            best = h;
            at = Some(i);
        }
    }
    (best, at)
}

/// "Always" along the sequence is the infimum over the index.
pub fn sequence_infimum(slacks: &[f64]) -> f64 {
    slacks.iter().copied().fold(f64::INFINITY, f64::min)
}

/// α(h) = h. Then ḣ ≥ −α(h) iff the next robustness is nonnegative.
/// A stay inside the set passes. A stay outside fails. No safe next state is refused.
pub fn barrier_holds(h_next: f64) -> bool {
    h_next.is_finite() && h_next >= 0.0
}

pub fn range_digest(rows: &[RuleRow]) -> String {
    let material = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "intervals": row.intervals,
                "controllable": row.controllable,
            })
        })
        .collect::<Vec<_>>();
    digest_json(&json!(material))
}

pub fn situation_digest(y: &[f64]) -> String {
    digest_json(&json!(y))
}

/// Seven memory slots, plus the address and the range digest the action path adds.
pub fn action_path_dna(
    agent: &str,
    task: &str,
    address: &str,
    range_digest: &str,
    y: &[f64],
    index: usize,
    auth_root: &str,
) -> Value {
    let var_digest = situation_digest(y);
    let index_key = index.to_string();
    let root = if auth_root.is_empty() {
        "genesis"
    } else {
        auth_root
    };
    let sequence_digest = digest_json(&json!({
        "agent_dna": agent,
        "type_dna": task,
        "cid": address,
        "data_digest": range_digest,
        "var_digest": var_digest,
        "index_key": index_key,
        "auth_root": root,
    }));
    json!({
        "schema": DNA_SCHEMA,
        "agent_dna": agent,
        "type_dna": task,
        "cid": address,
        "data_digest": range_digest,
        "var_digest": var_digest,
        "index_key": index_key,
        "auth_root": root,
        "sequence_digest": sequence_digest,
        "address": address,
        "range_digest": range_digest,
        "slot_count": 7,
    })
}

pub fn decide(input: &DecideInput<'_>) -> Value {
    let digest = range_digest(input.rows);
    let index = input.walk.committed.len();
    let dna = action_path_dna(
        input.agent,
        input.task,
        input.address,
        &digest,
        input.y,
        index,
        &input.walk.prev_digest,
    );
    let (h_now, row_now) = union_robustness(input.y, input.rows);
    let (h_next, row_at) = match input.proposed_y {
        Some(py) => union_robustness(py, input.rows),
        None => (h_now, row_now),
    };
    let measured = match input.proposed_y {
        Some(py) => py,
        None => input.y,
    };
    let row = row_at.and_then(|i| input.rows.get(i));
    let axis_slack: Vec<Value> = row
        .map(|r| {
            measured
                .iter()
                .zip(r.intervals.iter())
                .map(|(y, (r1, r2))| json_num(atomic_slack(*y, *r1, *r2)))
                .collect()
        })
        .unwrap_or_default();
    let controllable_move = row
        .map(|r| {
            measured
                .iter()
                .zip(r.intervals.iter())
                .enumerate()
                .any(|(j, (y, (r1, r2)))| {
                    r.controllable.get(j).copied().unwrap_or(false)
                        && atomic_slack(*y, *r1, *r2) < 0.0
                })
        })
        .unwrap_or(false);
    let cycle = input.walk.committed.iter().any(|step| {
        step.address == input.address && step.range_digest == digest
    });
    let barrier = barrier_holds(h_next);
    let shape_ok = !input.rows.is_empty()
        && input.y.iter().all(|v| v.is_finite())
        && input
            .proposed_y
            .map(|py| py.iter().all(|v| v.is_finite()) && py.len() == input.y.len())
            .unwrap_or(true)
        && row.is_some();
    let outcome = if !shape_ok {
        "situation_shape"
    } else if input.sealed {
        "seal"
    } else if !input.grant_edge {
        "no_grant"
    } else if cycle {
        "cycle"
    } else if input.proposed_y.is_some() && !barrier {
        "barrier"
    } else if h_next < 0.0 {
        if controllable_move {
            "adjust"
        } else {
            "change_address"
        }
    } else {
        "project"
    };
    let project = outcome == "project";
    let cover = project;
    let volume = if project {
        row.map(row_volume).unwrap_or(0.0)
    } else {
        0.0
    };
    let mut series: Vec<f64> = input
        .walk
        .committed
        .iter()
        .map(|s| s.robustness)
        .collect();
    if project && h_next.is_finite() {
        series.push(h_next);
    }
    let infimum = if series.is_empty() {
        h_next
    } else {
        sequence_infimum(&series)
    };
    json!({
        "schema": CHARTER_SCHEMA,
        "ok": true,
        "verbs": LOGIC_VERBS,
        "fence": "cease",
        "agent_pid": input.agent,
        "address": input.address,
        "address_type": input.address_type,
        "task": input.task,
        "robustness": json_num(h_next),
        "robustness_now": json_num(h_now),
        "sequence_infimum": json_num(infimum),
        "axis_slack": axis_slack,
        "matched_row": row.map(|r| r.id.clone()),
        "range_digest": digest,
        "sequence": dna,
        "barrier_holds": barrier,
        "grant_edge": input.grant_edge,
        "sealed": input.sealed,
        "cycle": cycle,
        "cover_added": cover,
        "cover_volume": json_num(volume),
        "controllable_move": controllable_move,
        "project": project,
        "outcome": outcome,
        "decision": "robustness",
        "honesty": "The decision is the robustness number. It is not Allow, Ask, or Block. Cease remains the operator fence and is not decided here.",
    })
}

pub fn parse_cell(value: &Value) -> Result<Interval, String> {
    if let Some(pair) = value.as_array() {
        if pair.len() != 2 {
            return Err("interval_needs_two_ends".into());
        }
        let lo = pair[0].as_f64().ok_or("interval_end_not_a_number")?;
        let hi = pair[1].as_f64().ok_or("interval_end_not_a_number")?;
        if !lo.is_finite() || !hi.is_finite() || hi < lo {
            return Err("interval_not_closed".into());
        }
        return Ok(Interval { lo, hi });
    }
    let op = value.get("op").and_then(|v| v.as_str()).unwrap_or("");
    if op == "add" {
        let a = parse_cell(value.get("a").ok_or("interval_add_missing_a")?)?;
        let b = parse_cell(value.get("b").ok_or("interval_add_missing_b")?)?;
        return Ok(a.add(b));
    }
    Err("interval_not_a_range".into())
}

pub fn parse_rows(value: &Value) -> Result<Vec<RuleRow>, String> {
    let rows = value.as_array().ok_or("rows_must_be_a_list")?;
    if rows.is_empty() || rows.len() > 32 {
        return Err("rows_count".into());
    }
    let mut out = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let id = row
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("a{}", i + 1));
        let cells = row
            .get("intervals")
            .and_then(|v| v.as_array())
            .ok_or("row_intervals")?;
        if cells.is_empty() || cells.len() > 16 {
            return Err("axis_count".into());
        }
        let mut intervals = Vec::with_capacity(cells.len());
        for cell in cells {
            let iv = parse_cell(cell)?;
            intervals.push((iv.lo, iv.hi));
        }
        let flags = row.get("controllable").and_then(|v| v.as_array());
        let controllable = (0..intervals.len())
            .map(|j| {
                flags
                    .and_then(|arr| arr.get(j))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .collect();
        out.push(RuleRow {
            id,
            intervals,
            controllable,
        });
    }
    Ok(out)
}

pub fn put_charter(state: &PlatformState, body: &Value) -> Result<Value, Value> {
    let goal_id = req_str(body, "goal_id")?;
    let agent = req_str(body, "agent_pid")?;
    let address = req_str(body, "address")?;
    let address_type = req_str(body, "address_type")?;
    let task = req_str(body, "task")?;
    let rows = parse_rows(body.get("rows").ok_or_else(|| {
        json!({"ok": false, "error": "rows_required"})
    })?)
    .map_err(|e| json!({"ok": false, "error": e}))?;
    let rec = json!({
        "schema": CHARTER_SCHEMA,
        "goal_id": goal_id,
        "agent_pid": agent,
        "address": address,
        "address_type": address_type,
        "task": task,
        "rows": body.get("rows").cloned().unwrap_or(Value::Null),
        "range_digest": range_digest(&rows),
        "verbs": LOGIC_VERBS,
    });
    store_put(state, CHARTER_FOLDER, &charter_key(&goal_id, &agent, &address, &task), &rec)?;
    Ok(json!({"ok": true, "charter": rec}))
}

pub fn step(state: &PlatformState, body: &Value) -> Result<Value, Value> {
    let goal_id = req_str(body, "goal_id")?;
    let agent = req_str(body, "agent_pid")?;
    let address = req_str(body, "address")?;
    let address_type = req_str(body, "address_type")?;
    let task = req_str(body, "task")?;
    let y = req_nums(body, "y")?;
    let proposed = body.get("proposed_y").and_then(|v| v.as_array()).map(|arr| {
        arr.iter().filter_map(|n| n.as_f64()).collect::<Vec<_>>()
    });
    let charter = load_charter(state, &goal_id, &agent, &address, &task)?;
    let rows = parse_rows(charter.get("rows").unwrap_or(&Value::Null))
        .map_err(|e| json!({"ok": false, "error": e}))?;
    let grant_edge = grant_edge_open(state, &agent, &address, &task);
    let sealed = crate::kernel::address_contracts::block_seal_active(state, &address, &task);
    let walk_key = walk_key(&goal_id, &agent);
    let walk_doc = store_get(state, WALK_FOLDER, &walk_key).unwrap_or_else(|| {
        json!({"goal_id": goal_id, "agent_pid": agent, "committed": []})
    });
    let memory = walk_memory(&walk_doc);
    let proposed_ref = proposed.as_deref();
    let mut receipt = decide(&DecideInput {
        agent: &agent,
        address: &address,
        address_type: &address_type,
        task: &task,
        y: &y,
        proposed_y: proposed_ref,
        rows: &rows,
        grant_edge,
        sealed,
        walk: &memory,
    });
    if receipt.get("project").and_then(|v| v.as_bool()).unwrap_or(false) {
        let mut committed = walk_doc
            .get("committed")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        committed.push(json!({
            "address": address,
            "address_type": address_type,
            "task": task,
            "range_digest": receipt.get("range_digest").cloned().unwrap_or(Value::Null),
            "sequence_digest": receipt.pointer("/sequence/sequence_digest").cloned().unwrap_or(Value::Null),
            "robustness": receipt.get("robustness").cloned().unwrap_or(Value::Null),
            "effect_taken": false,
        }));
        let saved = json!({
            "goal_id": goal_id,
            "agent_pid": agent,
            "committed": committed,
            "last_receipt": receipt,
        });
        store_put(state, WALK_FOLDER, &walk_key, &saved)?;
        let projected = store_projection(state, &agent, &receipt);
        if let Some(obj) = receipt.as_object_mut() {
            obj.insert("openshell_projection".into(), projected);
        }
    } else {
        let saved = json!({
            "goal_id": walk_doc.get("goal_id").cloned().unwrap_or(json!(goal_id)),
            "agent_pid": agent,
            "committed": walk_doc.get("committed").cloned().unwrap_or(json!([])),
            "last_receipt": receipt,
        });
        store_put(state, WALK_FOLDER, &walk_key, &saved)?;
    }
    if let Some(obj) = receipt.as_object_mut() {
        obj.insert("goal_id".into(), json!(goal_id));
    }
    Ok(receipt)
}

pub fn status(state: &PlatformState, goal_id: &str, agent: &str) -> Value {
    let walk = store_get(state, WALK_FOLDER, &walk_key(goal_id, agent)).unwrap_or(json!({
        "goal_id": goal_id,
        "agent_pid": agent,
        "committed": [],
    }));
    let charters = list_charters(state, goal_id, agent);
    json!({
        "ok": true,
        "verbs": LOGIC_VERBS,
        "fence": "cease",
        "walk": walk,
        "charters": charters,
        "honesty": "Robustness is the decision. Cease is the operator fence and is not a twelfth product.",
    })
}

/// Browser fetch is unchanged when no charter is bound. A bound charter must
/// project before the GET. Negative robustness does not fetch.
pub fn before_browser_fetch(
    state: &PlatformState,
    agent: &str,
    origin: &str,
    goal_id: Option<&str>,
    situation: Option<&[f64]>,
) -> Result<Option<Value>, Value> {
    let task = crate::kernel::browser_world::CAP_NAVIGATE;
    let matches = matching_charters(state, agent, origin, task);
    if matches.is_empty() {
        return Ok(None);
    }
    let goal = match goal_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(g) => g.to_string(),
        None if matches.len() == 1 => matches[0]
            .get("goal_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        None => {
            return Err(json!({
                "ok": false,
                "error": "goal_required",
                "fleet_chain": true,
                "address": origin,
            }));
        }
    };
    if let Some(y) = situation {
        let receipt = step(
            state,
            &json!({
                "goal_id": goal,
                "agent_pid": agent,
                "address": origin,
                "address_type": "browser",
                "task": task,
                "y": y,
            }),
        )?;
        if receipt.get("project").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Ok(Some(receipt));
        }
        return Err(json!({
            "ok": false,
            "error": "robustness_not_projected",
            "fleet_chain": receipt,
            "honesty": "Negative or non-project robustness does not fetch.",
        }));
    }
    match pending_projection(state, &goal, agent, origin, task) {
        Some(receipt) => Ok(Some(receipt)),
        None => Err(json!({
            "ok": false,
            "error": "situation_unmeasured",
            "fleet_chain": true,
            "goal_id": goal,
            "address": origin,
            "honesty": "A bound charter needs a measured situation before browse.navigate fetches.",
        })),
    }
}

pub fn mark_effect_taken(state: &PlatformState, goal_id: &str, agent: &str, sequence_digest: &str) {
    let key = walk_key(goal_id, agent);
    let Some(mut doc) = store_get(state, WALK_FOLDER, &key) else {
        return;
    };
    let Some(steps) = doc.get_mut("committed").and_then(|v| v.as_array_mut()) else {
        return;
    };
    for step in steps.iter_mut() {
        let digest = step
            .get("sequence_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if digest == sequence_digest {
            if let Some(obj) = step.as_object_mut() {
                obj.insert("effect_taken".into(), json!(true));
            }
        }
    }
    let _ = store_put(state, WALK_FOLDER, &key, &doc);
}

fn pending_projection(
    state: &PlatformState,
    goal_id: &str,
    agent: &str,
    address: &str,
    task: &str,
) -> Option<Value> {
    let doc = store_get(state, WALK_FOLDER, &walk_key(goal_id, agent))?;
    let steps = doc.get("committed")?.as_array()?;
    let pending = steps.iter().rev().find(|step| {
        step.get("address").and_then(|v| v.as_str()) == Some(address)
            && step.get("task").and_then(|v| v.as_str()) == Some(task)
            && step.get("effect_taken").and_then(|v| v.as_bool()) != Some(true)
    })?;
    Some(json!({
        "ok": true,
        "project": true,
        "outcome": "project",
        "goal_id": goal_id,
        "robustness": pending.get("robustness").cloned().unwrap_or(Value::Null),
        "sequence": {"sequence_digest": pending.get("sequence_digest").cloned().unwrap_or(Value::Null)},
        "range_digest": pending.get("range_digest").cloned().unwrap_or(Value::Null),
        "address": address,
        "reused_projection": true,
    }))
}

fn grant_edge_open(state: &PlatformState, agent: &str, address: &str, task: &str) -> bool {
    let Some(g) = crate::kernel::world_gateway::covering_grant(state, agent, address) else {
        return false;
    };
    if g.effect.eq_ignore_ascii_case("block") {
        return false;
    }
    if g.access.is_empty() {
        return true;
    }
    let task = task.to_ascii_lowercase();
    g.access.iter().any(|cap| {
        let cap = cap.to_ascii_lowercase();
        cap == task || cap == "*" || task.starts_with(&cap) || cap.starts_with(&task)
    })
}

fn matching_charters(state: &PlatformState, agent: &str, address: &str, task: &str) -> Vec<Value> {
    list_all(state, CHARTER_FOLDER)
        .into_iter()
        .filter(|v| {
            v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent)
                && v.get("address").and_then(|x| x.as_str()) == Some(address)
                && v.get("task").and_then(|x| x.as_str()) == Some(task)
        })
        .collect()
}

fn list_charters(state: &PlatformState, goal_id: &str, agent: &str) -> Vec<Value> {
    list_all(state, CHARTER_FOLDER)
        .into_iter()
        .filter(|v| {
            v.get("goal_id").and_then(|x| x.as_str()) == Some(goal_id)
                && v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent)
        })
        .collect()
}

fn load_charter(
    state: &PlatformState,
    goal_id: &str,
    agent: &str,
    address: &str,
    task: &str,
) -> Result<Value, Value> {
    store_get(state, CHARTER_FOLDER, &charter_key(goal_id, agent, address, task)).ok_or_else(
        || {
            json!({
                "ok": false,
                "error": "charter_missing",
                "honesty": "No matrix is consulted until a charter binds this goal, address, and task.",
            })
        },
    )
}

fn store_projection(state: &PlatformState, agent: &str, receipt: &Value) -> Value {
    let rec = json!({
        "schema": PROJECTION_SCHEMA,
        "source": "fleet_action_chain",
        "agent_pid": agent,
        "robustness": receipt.get("robustness").cloned().unwrap_or(Value::Null),
        "address": receipt.get("address").cloned().unwrap_or(Value::Null),
        "task": receipt.get("task").cloned().unwrap_or(Value::Null),
        "sequence_digest": receipt.pointer("/sequence/sequence_digest").cloned().unwrap_or(Value::Null),
        "pushed": false,
        "openshell_ready": false,
        "honesty": "A nonnegative robustness is stored as an OpenShell policy projection. This write does not push a policy and does not make OpenShell ready.",
    });
    let key = receipt
        .pointer("/sequence/sequence_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("missing")
        .to_string();
    match store_put(state, POLICY_GEN_FOLDER, &format!("fleet:{key}"), &rec) {
        Ok(()) => rec,
        Err(e) => e,
    }
}

fn walk_memory(doc: &Value) -> WalkMemory {
    let committed: Vec<CommittedStep> = doc
        .get("committed")
        .and_then(|v| v.as_array())
        .map(|steps| {
            steps
                .iter()
                .filter_map(|step| {
                    Some(CommittedStep {
                        address: step.get("address")?.as_str()?.to_string(),
                        range_digest: step.get("range_digest")?.as_str()?.to_string(),
                        sequence_digest: step
                            .get("sequence_digest")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        robustness: step.get("robustness").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        effect_taken: step
                            .get("effect_taken")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let prev_digest = committed
        .last()
        .map(|s| s.sequence_digest.clone())
        .unwrap_or_default();
    WalkMemory {
        committed,
        prev_digest,
    }
}

fn row_volume(row: &RuleRow) -> f64 {
    let mut volume = 1.0;
    for (lo, hi) in &row.intervals {
        let width = hi - lo;
        if width < 0.0 || !width.is_finite() {
            return 0.0;
        }
        volume *= width;
    }
    volume
}

fn charter_key(goal: &str, agent: &str, address: &str, task: &str) -> String {
    digest_json(&json!([goal, agent, address, task]))
}

fn walk_key(goal: &str, agent: &str) -> String {
    digest_json(&json!(["walk", goal, agent]))
}

fn digest_json(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).unwrap_or_default())
    )
}

fn json_num(n: f64) -> Value {
    if n.is_finite() {
        json!(n)
    } else {
        Value::Null
    }
}

fn req_str(body: &Value, key: &str) -> Result<String, Value> {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| json!({"ok": false, "error": format!("{key}_required")}))
}

fn req_nums(body: &Value, key: &str) -> Result<Vec<f64>, Value> {
    let arr = body
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| json!({"ok": false, "error": format!("{key}_required")}))?;
    if arr.is_empty() || arr.len() > 16 {
        return Err(json!({"ok": false, "error": "situation_shape"}));
    }
    let mut out = Vec::with_capacity(arr.len());
    for n in arr {
        let Some(x) = n.as_f64() else {
            return Err(json!({"ok": false, "error": "situation_shape"}));
        };
        out.push(x);
    }
    Ok(out)
}

fn store_put(state: &PlatformState, folder: &str, key: &str, value: &Value) -> Result<(), Value> {
    let mut es = state.engine_store.lock().map_err(|_| {
        json!({"ok": false, "error": "store_unavailable"})
    })?;
    es.folder_put(folder, key, value)
        .map_err(|e| json!({"ok": false, "error": "store_put_failed", "detail": e.to_string()}))
}

fn store_get(state: &PlatformState, folder: &str, key: &str) -> Option<Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(folder, key).ok().flatten()
}

fn list_all(state: &PlatformState, folder: &str) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let Ok(keys) = es.folder_keys(folder, None) else {
        return vec![];
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(folder, &k).ok().flatten())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, intervals: Vec<(f64, f64)>, controllable: Vec<bool>) -> RuleRow {
        RuleRow {
            id: id.into(),
            intervals,
            controllable,
        }
    }

    #[test]
    fn eleventh_is_cease_and_a_twelfth_name_is_rejected() {
        assert_eq!(LOGIC_VERBS.len(), 11);
        assert_eq!(LOGIC_VERBS[10], "cease");
        assert_eq!(parse_verb("cease").unwrap(), LogicVerb::Cease);
        assert_eq!(parse_verb("security"), Err("twelfth_verb_rejected"));
        assert_eq!(parse_verb("knot"), Err("twelfth_verb_rejected"));
        assert_eq!(parse_verb("allow"), Err("twelfth_verb_rejected"));
    }

    #[test]
    fn atomic_row_union_and_infimum() {
        assert_eq!(atomic_slack(5.0, 0.0, 10.0), 5.0);
        assert_eq!(atomic_slack(12.0, 0.0, 10.0), -2.0);
        let inside = row("a1", vec![(0.0, 10.0), (0.0, 4.0)], vec![true, false]);
        assert_eq!(row_robustness(&[5.0, 1.0], &inside.intervals), 1.0);
        assert_eq!(row_robustness(&[5.0, -1.0], &inside.intervals), -1.0);
        let other = row("a2", vec![(10.0, 12.0), (0.0, 4.0)], vec![false, false]);
        let (h, at) = union_robustness(&[11.0, 1.0], &[inside, other]);
        assert_eq!(h, 1.0);
        assert_eq!(at, Some(1));
        assert_eq!(sequence_infimum(&[1.0, 0.5, 2.0]), 0.5);
    }

    #[test]
    fn barrier_accepts_only_a_nonnegative_next_robustness() {
        assert!(barrier_holds(0.2));
        assert!(barrier_holds(0.0));
        assert!(!barrier_holds(-0.1));
        let rows = vec![row("a1", vec![(0.0, 10.0)], vec![true])];
        let walk = WalkMemory {
            committed: vec![],
            prev_digest: String::new(),
        };
        let y = [5.0];
        let proposed = [-1.0];
        let left = decide(&DecideInput {
            agent: "agent",
            address: "https://example.test",
            address_type: "browser",
            task: "browse.navigate",
            y: &y,
            proposed_y: Some(&proposed),
            rows: &rows,
            grant_edge: true,
            sealed: false,
            walk: &walk,
        });
        assert_eq!(left["outcome"], "barrier");
        assert_eq!(left["project"], false);
        let stayed = decide(&DecideInput {
            proposed_y: None,
            ..DecideInput {
                agent: "agent",
                address: "https://example.test",
                address_type: "browser",
                task: "browse.navigate",
                y: &y,
                proposed_y: None,
                rows: &rows,
                grant_edge: true,
                sealed: false,
                walk: &walk,
            }
        });
        assert_eq!(stayed["outcome"], "project");
        assert_eq!(stayed["robustness"], 5.0);
    }

    #[test]
    fn seal_overrides_a_positive_robustness() {
        let rows = vec![row("a1", vec![(0.0, 10.0)], vec![true])];
        let walk = WalkMemory {
            committed: vec![],
            prev_digest: String::new(),
        };
        let y = [5.0];
        let receipt = decide(&DecideInput {
            agent: "agent",
            address: "https://example.test",
            address_type: "browser",
            task: "browse.navigate",
            y: &y,
            proposed_y: None,
            rows: &rows,
            grant_edge: true,
            sealed: true,
            walk: &walk,
        });
        assert_eq!(receipt["robustness"], 5.0);
        assert_eq!(receipt["project"], false);
        assert_eq!(receipt["outcome"], "seal");
    }

    #[test]
    fn same_digest_is_the_same_step_and_a_repeat_is_a_cycle() {
        let rows = vec![row("a1", vec![(0.0, 1.0)], vec![false])];
        let y = [0.25];
        let first = action_path_dna("agent", "browse.navigate", "https://a.test", "range", &y, 0, "");
        let again = action_path_dna("agent", "browse.navigate", "https://a.test", "range", &y, 0, "");
        let moved = action_path_dna("agent", "browse.navigate", "https://b.test", "range", &y, 0, "");
        assert_eq!(first["sequence_digest"], again["sequence_digest"]);
        assert_ne!(first["sequence_digest"], moved["sequence_digest"]);
        assert_eq!(first["slot_count"], 7);
        let walk = WalkMemory {
            committed: vec![CommittedStep {
                address: "https://a.test".into(),
                range_digest: range_digest(&rows),
                sequence_digest: "prev".into(),
                robustness: 0.25,
                effect_taken: true,
            }],
            prev_digest: "prev".into(),
        };
        let cycle = decide(&DecideInput {
            agent: "agent",
            address: "https://a.test",
            address_type: "browser",
            task: "browse.navigate",
            y: &y,
            proposed_y: None,
            rows: &rows,
            grant_edge: true,
            sealed: false,
            walk: &walk,
        });
        assert_eq!(cycle["outcome"], "cycle");
        assert_eq!(cycle["project"], false);
        let other_rows = vec![row("a1", vec![(0.0, 2.0)], vec![false])];
        let revisit = decide(&DecideInput {
            rows: &other_rows,
            ..DecideInput {
                agent: "agent",
                address: "https://a.test",
                address_type: "browser",
                task: "browse.navigate",
                y: &y,
                proposed_y: None,
                rows: &other_rows,
                grant_edge: true,
                sealed: false,
                walk: &walk,
            }
        });
        assert_eq!(revisit["outcome"], "project");
        assert_eq!(revisit["cover_added"], true);
    }

    #[test]
    fn browser_and_http_api_share_the_robustness_number() {
        let rows = vec![row("a1", vec![(0.0, 10.0), (10.0, 20.0)], vec![true, false])];
        let walk = WalkMemory {
            committed: vec![],
            prev_digest: String::new(),
        };
        let y = [4.0, 12.0];
        let browser = decide(&DecideInput {
            agent: "agent",
            address: "https://docs.test",
            address_type: "browser",
            task: "browse.navigate",
            y: &y,
            proposed_y: None,
            rows: &rows,
            grant_edge: true,
            sealed: false,
            walk: &walk,
        });
        let http = decide(&DecideInput {
            address: "https://api.test/v1",
            address_type: "http_api",
            task: "http.get",
            ..DecideInput {
                agent: "agent",
                address: "https://api.test/v1",
                address_type: "http_api",
                task: "http.get",
                y: &y,
                proposed_y: None,
                rows: &rows,
                grant_edge: true,
                sealed: false,
                walk: &walk,
            }
        });
        assert_eq!(browser["robustness"], http["robustness"]);
        assert_eq!(browser["robustness"], 2.0);
        assert_ne!(browser["address_type"], http["address_type"]);
        let outside = [30.0, 12.0];
        let adjust = decide(&DecideInput {
            y: &outside,
            ..DecideInput {
                agent: "agent",
                address: "https://api.test/v1",
                address_type: "a2a_task",
                task: "a2a.send",
                y: &outside,
                proposed_y: None,
                rows: &rows,
                grant_edge: true,
                sealed: false,
                walk: &walk,
            }
        });
        assert_eq!(adjust["outcome"], "adjust");
        assert_eq!(adjust["project"], false);
        let no_control = vec![row("a1", vec![(0.0, 10.0), (10.0, 20.0)], vec![false, false])];
        let change = decide(&DecideInput {
            rows: &no_control,
            ..DecideInput {
                agent: "agent",
                address: "https://api.test/v1",
                address_type: "a2a_task",
                task: "a2a.send",
                y: &outside,
                proposed_y: None,
                rows: &no_control,
                grant_edge: true,
                sealed: false,
                walk: &walk,
            }
        });
        assert_eq!(change["outcome"], "change_address");
    }

    #[test]
    fn derived_interval_contains_the_true_sum() {
        let sum = Interval { lo: 0.1, hi: 0.2 }.add(Interval { lo: 0.1, hi: 0.2 });
        assert!(sum.lo <= 0.2);
        assert!(sum.hi >= 0.4);
        let parsed = parse_cell(&json!({"op": "add", "a": [0.1, 0.2], "b": [0.1, 0.2]})).unwrap();
        assert!(parsed.lo <= 0.2 && parsed.hi >= 0.4);
    }

    #[test]
    fn negative_on_an_uncontrollable_axis_changes_address() {
        let rows = vec![row("a1", vec![(0.0, 1.0)], vec![false])];
        let walk = WalkMemory {
            committed: vec![],
            prev_digest: String::new(),
        };
        let y = [3.0];
        let receipt = decide(&DecideInput {
            agent: "agent",
            address: "https://example.test",
            address_type: "http_api",
            task: "http.get",
            y: &y,
            proposed_y: None,
            rows: &rows,
            grant_edge: true,
            sealed: false,
            walk: &walk,
        });
        assert_eq!(receipt["outcome"], "change_address");
        assert!(receipt.get("decision").and_then(|v| v.as_str()) == Some("robustness"));
        assert!(receipt.get("verdict").is_none());
    }
}
