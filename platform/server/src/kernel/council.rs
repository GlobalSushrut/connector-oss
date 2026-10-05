//! Intelligence council — sibling `I` cells under a human+root mint.
//!
//! Isolated by default. Root setup mints the council and pairwise share pores.
//! Members speak on a hash-chained floor. Identity is `μ` (0xCD), not Linux PID.
//! No ambient `/k`. No speaking as another `I`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::kernel::intelligence_spec;
use crate::kernel::matrix_host_egress;
use crate::kernel::share_portal::{self, ShareContractV1};
use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.council.v1";
pub const COUNCIL_FOLDER: &str = "iia_councils_v1";
pub const FLOOR_FOLDER: &str = "iia_council_floor_v1";

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilMember {
    pub I: String,
    pub mu: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilV1 {
    pub council_id: String,
    pub name: String,
    pub members: Vec<CouncilMember>,
    pub portal_ids: Vec<String>,
    pub justification: String,
    pub created_at: String,
    pub closed: bool,
    pub floor_seq: u64,
    pub floor_head: String,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloorEntry {
    pub seq: u64,
    pub council_id: String,
    pub from_I: String,
    pub from_mu: String,
    pub from_name: String,
    pub to: String,
    pub kind: String,
    pub body: String,
    #[serde(default)]
    pub task_id: String,
    pub prev_hash: String,
    pub record_hash: String,
    pub ts: String,
}

/// Named work with a living owner `μ`. Crew/AutoGen skip this and share one process.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilTaskV1 {
    pub task_id: String,
    pub council_id: String,
    pub from_I: String,
    pub from_mu: String,
    pub owner_I: String,
    pub owner_mu: String,
    pub body: String,
    pub status: String,
    pub opened_seq: u64,
    pub last_seq: u64,
}

pub const TASK_FOLDER: &str = "iia_council_tasks_v1";

pub fn identity_card(state: &PlatformState, pid: &str) -> CouncilMember {
    let pid = pid.trim().to_string();
    let mu = matrix_host_egress::intelligence_egress_mark_hex(&pid);
    let name = intelligence_spec::load_spec_doc(state, &pid)
        .and_then(|s| {
            s.pointer("/metadata/name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            crate::kernel::agent_identity_envelope::load_setup(state, &pid).map(|s| s.name)
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| pid.clone());
    CouncilMember {
        I: pid,
        mu,
        name,
    }
}

fn member_exists(state: &PlatformState, pid: &str) -> bool {
    if intelligence_spec::load_spec_doc(state, pid).is_some() {
        return true;
    }
    if crate::kernel::agent_identity_envelope::load_setup(state, pid).is_some() {
        return true;
    }
    state
        .kernel
        .lock()
        .ok()
        .and_then(|k| k.get_agent(pid).map(|_| ()))
        .is_some()
}

fn council_id(name: &str, members: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(name.trim().as_bytes());
    let mut m = members.to_vec();
    m.sort();
    for p in m {
        h.update(0u8.to_be_bytes());
        h.update(p.trim().as_bytes());
    }
    format!("cnc_{}", hex::encode(&h.finalize()[..12]))
}

fn hash_entry(e: &FloorEntry) -> String {
    let material = json!({
        "seq": e.seq,
        "council_id": e.council_id,
        "from_I": e.from_I,
        "from_mu": e.from_mu,
        "to": e.to,
        "kind": e.kind,
        "body": e.body,
        "task_id": e.task_id,
        "prev_hash": e.prev_hash,
        "ts": e.ts,
    });
    let bytes = serde_json::to_vec(&crate::kernel::action_binding::canonical_json(&material))
        .unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

pub fn load(state: &PlatformState, council_id: &str) -> Option<CouncilV1> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(COUNCIL_FOLDER, council_id.trim()).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn save(state: &PlatformState, c: &CouncilV1) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    es.folder_put(
        COUNCIL_FOLDER,
        &c.council_id,
        &serde_json::to_value(c).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())
}

pub fn list(state: &PlatformState, agent_pid: Option<&str>) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let Ok(keys) = es.folder_keys(COUNCIL_FOLDER, None) else {
        return vec![];
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(COUNCIL_FOLDER, &k).ok().flatten())
        .filter(|c| {
            let Some(want) = agent_pid.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
                return true;
            };
            c.get("members")
                .and_then(|m| m.as_array())
                .map(|arr| {
                    arr.iter()
                        .any(|m| m.get("I").and_then(|x| x.as_str()) == Some(want))
                })
                .unwrap_or(false)
        })
        .collect()
}

pub fn is_member(c: &CouncilV1, pid: &str) -> bool {
    let p = pid.trim();
    c.members.iter().any(|m| m.I == p)
}

fn mint_task_id(council_id: &str, seq: u64, from: &str, to: &str) -> String {
    let mut h = Sha256::new();
    h.update(council_id.as_bytes());
    h.update(seq.to_be_bytes());
    h.update(from.as_bytes());
    h.update(to.as_bytes());
    format!("tsk_{}", hex::encode(&h.finalize()[..12]))
}

fn load_task(state: &PlatformState, task_id: &str) -> Option<CouncilTaskV1> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(TASK_FOLDER, task_id.trim()).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn save_task(state: &PlatformState, t: &CouncilTaskV1) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    es.folder_put(
        TASK_FOLDER,
        &t.task_id,
        &serde_json::to_value(t).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())
}

pub fn list_tasks(state: &PlatformState, council_id: &str) -> Vec<CouncilTaskV1> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let Ok(keys) = es.folder_keys(TASK_FOLDER, None) else {
        return vec![];
    };
    let want = council_id.trim();
    keys.into_iter()
        .filter_map(|k| es.folder_get(TASK_FOLDER, &k).ok().flatten())
        .filter_map(|v| serde_json::from_value::<CouncilTaskV1>(v).ok())
        .filter(|t| t.council_id == want)
        .collect()
}

fn member_mu<'a>(c: &'a CouncilV1, pid: &str) -> Option<&'a str> {
    c.members
        .iter()
        .find(|m| m.I == pid.trim())
        .map(|m| m.mu.as_str())
}

/// Human+root mints a council. Pairwise pores so members may address each other.
pub fn mint(
    state: &PlatformState,
    name: &str,
    member_pids: &[String],
    justification: &str,
) -> Result<CouncilV1, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("council_name_required".into());
    }
    if justification.trim().len() < 16 {
        return Err("council_requires_justification (min 16 chars: who, why, what they may say)".into());
    }
    let mut uniq = Vec::new();
    for p in member_pids {
        let p = p.trim().to_string();
        if p.is_empty() {
            continue;
        }
        if !uniq.iter().any(|x: &String| x == &p) {
            uniq.push(p);
        }
    }
    if uniq.len() < 2 {
        return Err("council_needs_at_least_two_I".into());
    }
    for p in &uniq {
        if !member_exists(state, p) {
            return Err(format!("unknown_intelligence: {p} — charter I first"));
        }
    }
    let id = council_id(name, &uniq);
    if load(state, &id).is_some() {
        return Err("council_already_exists".into());
    }
    let members: Vec<CouncilMember> = uniq.iter().map(|p| identity_card(state, p)).collect();
    let mut portal_ids = Vec::new();
    let what = format!("council:{id}");
    let r#where = format!("/share/council/{id}");
    for i in 0..uniq.len() {
        for j in (i + 1)..uniq.len() {
            let contract = ShareContractV1 {
                from_pid: uniq[i].clone(),
                to_pid: uniq[j].clone(),
                what: what.clone(),
                r#where: r#where.clone(),
                bytes_max: 1_048_576,
                packets_max: 10_000,
                ttl_ms: 30 * 24 * 3600 * 1000,
                permissions: vec!["read".into(), "write".into()],
                justification: format!("council {name}: {justification}"),
            };
            let portal = share_portal::put_portal(state, &contract)?;
            portal_ids.push(portal.portal_id);
        }
    }
    let c = CouncilV1 {
        council_id: id.clone(),
        name: name.to_string(),
        members,
        portal_ids,
        justification: justification.trim().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        closed: false,
        floor_seq: 0,
        floor_head: "genesis".into(),
    };
    save(state, &c)?;
    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        "root",
        "council.mint",
        true,
        &json!({ "council_id": id, "members": uniq.len() }),
    );
    Ok(c)
}

pub fn add_member(state: &PlatformState, council_id: &str, pid: &str) -> Result<CouncilV1, String> {
    let mut c = load(state, council_id).ok_or_else(|| "council_not_found".to_string())?;
    if c.closed {
        return Err("council_closed".into());
    }
    let pid = pid.trim();
    if !member_exists(state, pid) {
        return Err(format!("unknown_intelligence: {pid}"));
    }
    if is_member(&c, pid) {
        return Ok(c);
    }
    let card = identity_card(state, pid);
    let what = format!("council:{}", c.council_id);
    let r#where = format!("/share/council/{}", c.council_id);
    for existing in c.members.clone() {
        let contract = ShareContractV1 {
            from_pid: existing.I.clone(),
            to_pid: pid.to_string(),
            what: what.clone(),
            r#where: r#where.clone(),
            bytes_max: 1_048_576,
            packets_max: 10_000,
            ttl_ms: 30 * 24 * 3600 * 1000,
            permissions: vec!["read".into(), "write".into()],
            justification: format!("council {}: add {}", c.name, pid),
        };
        let portal = share_portal::put_portal(state, &contract)?;
        c.portal_ids.push(portal.portal_id);
    }
    c.members.push(card);
    save(state, &c)?;
    Ok(c)
}

pub fn close(state: &PlatformState, council_id: &str) -> Result<CouncilV1, String> {
    let mut c = load(state, council_id).ok_or_else(|| "council_not_found".to_string())?;
    for pid in c.portal_ids.clone() {
        let _ = share_portal::close_portal(state, &pid);
    }
    c.closed = true;
    save(state, &c)?;
    Ok(c)
}

/// Speak / task / ack / done / refuse / handoff on the floor.
/// `to` = "floor" (broadcast) or a member `I`. Tasks and handoffs require a named `I`.
/// Identity is recomputed. Client-supplied μ that does not match is refused.
pub fn speak(
    state: &PlatformState,
    council_id: &str,
    from_pid: &str,
    to: &str,
    kind: &str,
    body: &str,
    claimed_mu: Option<&str>,
    task_ref: Option<&str>,
) -> Result<FloorEntry, String> {
    let mut c = load(state, council_id).ok_or_else(|| "council_not_found".to_string())?;
    if c.closed {
        return Err("council_closed".into());
    }
    let from_pid = from_pid.trim();
    if !is_member(&c, from_pid) {
        return Err("not_a_member".into());
    }
    let live = identity_card(state, from_pid);
    if let Some(claim) = claimed_mu.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if claim != live.mu {
            return Err(format!(
                "identity_mismatch: claimed μ {claim} ≠ live {} for I {from_pid}. Cannot speak as another intelligence.",
                live.mu
            ));
        }
    }
    if member_mu(&c, from_pid) != Some(live.mu.as_str()) {
        return Err(format!(
            "roster_mu_stale: re-mint council or add_member. roster={} live={}",
            member_mu(&c, from_pid).unwrap_or("?"),
            live.mu
        ));
    }
    let kind = match kind.trim().to_ascii_lowercase().as_str() {
        "task" => "task",
        "ack" => "ack",
        "done" => "done",
        "refuse" => "refuse",
        "handoff" => "handoff",
        _ => "speak",
    };
    let to = to.trim();
    let to_norm = if to.is_empty() || to == "*" || to.eq_ignore_ascii_case("floor") {
        "floor".to_string()
    } else {
        if !is_member(&c, to) {
            return Err("addressee_not_a_member".into());
        }
        if to == from_pid && kind != "ack" && kind != "done" && kind != "refuse" {
            return Err("speak_to_self_nonsensical".into());
        }
        to.to_string()
    };
    if kind == "task" && to_norm == "floor" {
        return Err("task_requires_assignee_I — name the I who owns the work. Market crews skip this and share a process.".into());
    }
    if kind == "handoff" && to_norm == "floor" {
        return Err("handoff_requires_assignee_I".into());
    }
    let body = body.trim();
    if body.is_empty() {
        return Err("body_required".into());
    }
    if body.len() > 16_384 {
        return Err("body_too_large".into());
    }
    crate::kernel::agent_principal::require_contract_action(
        state,
        from_pid,
        "council.speak",
        &c.council_id,
    )?;

    let seq = c.floor_seq.saturating_add(1);
    let mut task_id = String::new();
    let mut task_update: Option<CouncilTaskV1> = None;
    match kind {
        "task" => {
            task_id = mint_task_id(&c.council_id, seq, from_pid, &to_norm);
            let owner = identity_card(state, &to_norm);
            task_update = Some(CouncilTaskV1 {
                task_id: task_id.clone(),
                council_id: c.council_id.clone(),
                from_I: live.I.clone(),
                from_mu: live.mu.clone(),
                owner_I: owner.I,
                owner_mu: owner.mu,
                body: body.to_string(),
                status: "open".into(),
                opened_seq: seq,
                last_seq: seq,
            });
        }
        "ack" | "done" | "refuse" | "handoff" => {
            let tid = task_ref
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "task_id_required".to_string())?;
            let mut t = load_task(state, tid).ok_or_else(|| "task_not_found".to_string())?;
            if t.council_id != c.council_id {
                return Err("task_not_in_this_council".into());
            }
            if t.owner_I != from_pid {
                return Err(format!(
                    "not_task_owner: owner is {} μ {} — you are {} μ {}. Cannot act as another I.",
                    t.owner_I, t.owner_mu, from_pid, live.mu
                ));
            }
            if t.status == "done" || t.status == "refused" {
                return Err("task_already_closed".into());
            }
            task_id = t.task_id.clone();
            t.last_seq = seq;
            match kind {
                "ack" => t.status = "accepted".into(),
                "done" => t.status = "done".into(),
                "refuse" => t.status = "refused".into(),
                "handoff" => {
                    if to_norm == from_pid {
                        return Err("handoff_to_self_nonsensical".into());
                    }
                    let next = identity_card(state, &to_norm);
                    t.owner_I = next.I;
                    t.owner_mu = next.mu;
                    if t.status == "open" {
                        t.status = "open".into();
                    }
                }
                _ => {}
            }
            task_update = Some(t);
        }
        _ => {}
    }

    let ts = chrono::Utc::now().to_rfc3339();
    let mut entry = FloorEntry {
        seq,
        council_id: c.council_id.clone(),
        from_I: live.I.clone(),
        from_mu: live.mu.clone(),
        from_name: live.name.clone(),
        to: to_norm.clone(),
        kind: kind.into(),
        body: body.to_string(),
        task_id: task_id.clone(),
        prev_hash: c.floor_head.clone(),
        record_hash: String::new(),
        ts,
    };
    entry.record_hash = hash_entry(&entry);
    let floor_key = format!("{}:{:08}", c.council_id, seq);
    {
        let mut es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        es.folder_put(
            FLOOR_FOLDER,
            &floor_key,
            &serde_json::to_value(&entry).unwrap_or(Value::Null),
        )
        .map_err(|e| e.to_string())?;
    }
    c.floor_seq = seq;
    c.floor_head = entry.record_hash.clone();
    save(state, &c)?;
    if let Some(t) = task_update {
        save_task(state, &t)?;
    }

    let line = format!(
        "[council {} | {} {} → {} | {} {}] {}",
        c.name,
        entry.from_mu,
        entry.from_name,
        entry.to,
        entry.kind,
        if entry.task_id.is_empty() {
            String::new()
        } else {
            entry.task_id.clone()
        },
        entry.body
    );
    let clip: String = line.chars().take(2000).collect();
    if to_norm == "floor" {
        for m in &c.members {
            if m.I != from_pid {
                let _ = crate::kernel::aios::recall_append(&m.I, "council", &clip);
            }
        }
    } else {
        let _ = crate::kernel::aios::recall_append(&to_norm, "council", &clip);
        if kind == "handoff" {
            // previous owner already appended below; new owner got the directed line
        }
    }
    let _ = crate::kernel::aios::recall_append(from_pid, "council", &clip);

    crate::kernel::decision_trace::append_trace(
        state,
        from_pid,
        crate::kernel::decision_trace::TraceAppendOpts {
            gateway: "allow".into(),
            action_digest: Some(entry.record_hash.clone()),
            outcome: format!("council.{}:{}:{}", kind, c.council_id, entry.seq),
            ..Default::default()
        },
    );
    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        from_pid,
        "council.speak",
        true,
        &json!({
            "council_id": c.council_id,
            "seq": seq,
            "from_mu": entry.from_mu,
            "to": entry.to,
            "kind": entry.kind,
            "task_id": entry.task_id,
        }),
    );
    Ok(entry)
}

pub fn floor(state: &PlatformState, council_id: &str, limit: usize) -> Result<Value, String> {
    let c = load(state, council_id).ok_or_else(|| "council_not_found".to_string())?;
    let cap = limit.max(1).min(200);
    let es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let mut entries = Vec::new();
    let start = c.floor_seq.saturating_sub(cap as u64 - 1).max(1);
    for seq in start..=c.floor_seq {
        let key = format!("{}:{:08}", c.council_id, seq);
        if let Ok(Some(v)) = es.folder_get(FLOOR_FOLDER, &key) {
            entries.push(v);
        }
    }
    Ok(json!({
        "ok": true,
        "schema": SCHEMA,
        "council_id": c.council_id,
        "name": c.name,
        "closed": c.closed,
        "floor_seq": c.floor_seq,
        "floor_head": c.floor_head,
        "entries": entries,
        "honesty": "Hash-chained floor. Identity is μ on every line. Tasks have an owner μ. Not a shared brain."
    }))
}

/// This I's desk: open work owned by them + recent lines they may see.
pub fn inbox(state: &PlatformState, pid: &str) -> Value {
    let pid = pid.trim();
    let councils = list(state, Some(pid));
    let mut desks = Vec::new();
    let mut my_tasks = Vec::new();
    let mut recent = Vec::new();
    for raw in &councils {
        let id = raw.get("council_id").and_then(|x| x.as_str()).unwrap_or("");
        if id.is_empty() {
            continue;
        }
        let closed = raw.get("closed").and_then(|x| x.as_bool()).unwrap_or(false);
        if closed {
            continue;
        }
        let name = raw.get("name").and_then(|x| x.as_str()).unwrap_or(id);
        let members = raw.get("members").cloned().unwrap_or(json!([]));
        desks.push(json!({
            "council_id": id,
            "name": name,
            "members": members,
        }));
        for t in list_tasks(state, id) {
            if t.owner_I == pid && (t.status == "open" || t.status == "accepted") {
                my_tasks.push(t);
            }
        }
        if let Ok(floor) = floor(state, id, 12) {
            if let Some(entries) = floor.get("entries").and_then(|e| e.as_array()) {
                for e in entries {
                    let to = e.get("to").and_then(|x| x.as_str()).unwrap_or("");
                    let from = e.get("from_I").and_then(|x| x.as_str()).unwrap_or("");
                    if to == "floor" || to == pid || from == pid {
                        recent.push(e.clone());
                    }
                }
            }
        }
    }
    if recent.len() > 24 {
        let skip = recent.len() - 24;
        recent = recent[skip..].to_vec();
    }
    json!({
        "ok": true,
        "schema": SCHEMA,
        "I": pid,
        "mu": crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(pid),
        "councils": desks,
        "tasks": my_tasks,
        "recent": recent,
        "honesty": "Crew/AutoGen share one process and invent speaker names. This desk is your I only. Tasks have an owner μ. Speak as yourself."
    })
}

/// Injected into Talk so LangGraph/Crew on /v1 actually see the council.
pub fn desk_prompt(state: &PlatformState, pid: &str) -> String {
    let v = inbox(state, pid);
    let councils = v.get("councils").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    if councils.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "--- CONNECTOR COUNCIL DESK (you are this I only; μ is identity; not a shared crew) ---\n",
    );
    for c in &councils {
        let id = c.get("council_id").and_then(|x| x.as_str()).unwrap_or("");
        let name = c.get("name").and_then(|x| x.as_str()).unwrap_or(id);
        out.push_str(&format!("Council {name} ({id}) members:"));
        if let Some(ms) = c.get("members").and_then(|m| m.as_array()) {
            for m in ms {
                let i = m.get("I").and_then(|x| x.as_str()).unwrap_or("?");
                let mu = m.get("mu").and_then(|x| x.as_str()).unwrap_or("?");
                let n = m.get("name").and_then(|x| x.as_str()).unwrap_or(i);
                out.push_str(&format!(" {n} I={i} μ={mu};"));
            }
        }
        out.push('\n');
    }
    if let Some(tasks) = v.get("tasks").and_then(|t| t.as_array()) {
        if tasks.is_empty() {
            out.push_str("Open tasks you own: none.\n");
        } else {
            out.push_str("Open tasks you own:\n");
            for t in tasks.iter().take(8) {
                let tid = t.get("task_id").and_then(|x| x.as_str()).unwrap_or("?");
                let st = t.get("status").and_then(|x| x.as_str()).unwrap_or("open");
                let from_mu = t.get("from_mu").and_then(|x| x.as_str()).unwrap_or("?");
                let body = t.get("body").and_then(|x| x.as_str()).unwrap_or("");
                let clip: String = body.chars().take(240).collect();
                out.push_str(&format!("  {st} {tid} from μ={from_mu}: {clip}\n"));
            }
        }
    }
    if let Some(recent) = v.get("recent").and_then(|t| t.as_array()) {
        if !recent.is_empty() {
            out.push_str("Recent floor (who said what):\n");
            for e in recent.iter().rev().take(8).collect::<Vec<_>>().into_iter().rev() {
                let seq = e.get("seq").and_then(|x| x.as_u64()).unwrap_or(0);
                let mu = e.get("from_mu").and_then(|x| x.as_str()).unwrap_or("?");
                let name = e.get("from_name").and_then(|x| x.as_str()).unwrap_or("?");
                let to = e.get("to").and_then(|x| x.as_str()).unwrap_or("floor");
                let kind = e.get("kind").and_then(|x| x.as_str()).unwrap_or("speak");
                let body = e.get("body").and_then(|x| x.as_str()).unwrap_or("");
                let clip: String = body.chars().take(160).collect();
                out.push_str(&format!("  #{seq} {kind} {name} μ={mu} → {to}: {clip}\n"));
            }
        }
    }
    out.push_str(
        "Act via POST /kernel/syscall op=council.speak (kind=speak|task|ack|done|refuse|handoff). Header I must be you. task requires to=<member I>. ack/done/refuse/handoff require task_id. Do not invent another member's μ.\n",
    );
    if out.len() > 3500 {
        out.truncate(3497);
        out.push_str("...");
    }
    out
}

pub fn snapshot(state: &PlatformState, council_id: &str) -> Result<Value, String> {
    let c = load(state, council_id).ok_or_else(|| "council_not_found".to_string())?;
    Ok(json!({
        "ok": true,
        "schema": SCHEMA,
        "council_id": c.council_id,
        "name": c.name,
        "closed": c.closed,
        "justification": c.justification,
        "created_at": c.created_at,
        "members": c.members,
        "tasks": list_tasks(state, &c.council_id),
        "floor_seq": c.floor_seq,
        "floor_head": c.floor_head,
        "honesty": "Root-minted. Pairwise pores. Each I keeps its WM. Floor is who-said-what. Tasks have a living owner μ — not a shared crew RAM."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn council_id_is_stable_and_order_insensitive() {
        let a = council_id("shop", &["b".into(), "a".into()]);
        let b = council_id("shop", &["a".into(), "b".into()]);
        assert_eq!(a, b);
        assert!(a.starts_with("cnc_"));
    }

    #[test]
    fn floor_hash_changes_with_speaker() {
        let mut e = FloorEntry {
            seq: 1,
            council_id: "cnc_x".into(),
            from_I: "agt_a".into(),
            from_mu: "0xcd000001".into(),
            from_name: "A".into(),
            to: "floor".into(),
            kind: "speak".into(),
            body: "hello".into(),
            task_id: String::new(),
            prev_hash: "genesis".into(),
            record_hash: String::new(),
            ts: "t".into(),
        };
        let h1 = hash_entry(&e);
        e.from_I = "agt_b".into();
        e.from_mu = "0xcd000002".into();
        let h2 = hash_entry(&e);
        assert_ne!(h1, h2);
        e.from_I = "agt_a".into();
        e.from_mu = "0xcd000001".into();
        e.task_id = "tsk_1".into();
        let h3 = hash_entry(&e);
        assert_ne!(h1, h3);
    }

    #[test]
    fn task_id_is_stable_and_names_assignee() {
        let a = mint_task_id("cnc_x", 1, "agt_a", "agt_b");
        let b = mint_task_id("cnc_x", 1, "agt_a", "agt_b");
        let c = mint_task_id("cnc_x", 1, "agt_a", "agt_c");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("tsk_"));
    }
}
