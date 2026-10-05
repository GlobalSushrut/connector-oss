//! Agentic Character Surface (ACS) — top-level view of one intelligence.
//!
//! Character (who it is / what it may be) + isolation (how it is caged) +
//! NS FS (where its world lives) + world grants (what addresses it may touch).
//! One document so operators and other agents do not hunt plugin settings.

use serde_json::{json, Value};

use crate::kernel::{intelligence_spec, isolation_tiers, nsfs, world_gateway};
use crate::state::PlatformState;

pub const ACS_SCHEMA: &str = "connector.acs.v1";

pub fn render(state: &PlatformState, agent_pid: &str) -> Value {
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return json!({"ok": false, "error": "agent_pid_required", "schema": ACS_SCHEMA});
    }
    let spec = intelligence_spec::load_spec_doc(state, pid);
    let skills = intelligence_spec::load_bound_skills(state, pid);
    let portals = intelligence_spec::load_portals(state, pid);
    let rules = intelligence_spec::load_rules(state, pid);
    let isolation = isolation_tiers::isolation_for_agent(state, pid);
    let ns = nsfs::snapshot(pid);
    let grants = world_gateway::list_grants(state, Some(pid));
    json!({
        "ok": true,
        "schema": ACS_SCHEMA,
        "agent_pid": pid,
        "character": {
            "name": spec.as_ref().and_then(|s| s.pointer("/metadata/name")).and_then(|x| x.as_str()),
            "class": spec.as_ref().and_then(|s| s.pointer("/spec/class")).and_then(|x| x.as_str()),
            "purpose": spec.as_ref().and_then(|s| s.pointer("/spec/purpose")).and_then(|x| x.as_str()),
            "harden": spec.as_ref().and_then(|s| s.pointer("/spec/harden")).and_then(|x| x.as_bool()),
            "namespace": spec.as_ref().and_then(|s| s.pointer("/spec/parameters/namespace")).and_then(|x| x.as_str()),
            "skills": skills,
            "portals": portals,
            "rules": rules,
        },
        "isolation": isolation,
        "density": isolation_tiers::light_isolation_profile(),
        "nsfs": ns,
        "cage": crate::kernel::address_cage::cage_snapshot(state, pid),
        "world": {
            "grant_count": grants.len(),
            "grants": grants,
            "layers": crate::kernel::admission_layers::catalog(),
            "types": crate::kernel::address_cage::types_catalog(),
            "local_host_address": crate::kernel::address_cage::LOCAL_HOST_ADDR,
            "gartner": "Root/Cone = L3 act-with-approval. App = L4 (kill + compensate). Uniform lock-or-trust fails.",
            "honesty": "Outer world is an address cage (this computer, APIs, tools, IoT, robots). Same machine ≠ host USER. Each (this pid × address) is its own grant. Cone/root Ask until HITL. App Allow only with justification. ACS does not share world access across agents.",
        },
        "matrix": crate::kernel::intelligence_matrix::cell(state, pid),
        "share": crate::kernel::share_portal::snapshot(state, pid),
        "councils": crate::kernel::council::list(state, Some(pid)),
        "operate": crate::kernel::operating_layer::cell_operate_slim(state, pid),
        "honesty": "ACS is private to this pid. Agent A cannot see Agent B. Share only via a human+root sharing contract that mints a portal. Council = root-minted floor with μ on every line — not a shared brain. Matrix = Albus SP·WM·VJ·BG. LangGraph and tools are BG app-layer — kernel does not import them.",
    })
}
