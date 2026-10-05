//! Honest ecosystem conformance. TARGET is not PASS.
//!
//! `connectorctl govern ecosystem` and `GET /api/v1/runtime/ecosystem` both
//! return this report. A check is PASS only when this process enforces the
//! property today. Everything else stays PARTIAL or TARGET.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use connector_trust::{sign_json_ed25519, verify_signed_payload_v2};

use super::runtime_adapter::{self, RuntimeKind};

pub const SCHEMA: &str = "connector.ecosystem_conformance.v1";

pub fn report() -> Value {
    let probes = runtime_adapter::probe_all();
    let supply = runtime_adapter::cosign_status();
    let backend_view = super::backends::assemble(&probes, &supply);
    let openshell = probes
        .iter()
        .find(|p| p.kind == RuntimeKind::OpenShell)
        .cloned();
    let firecracker = probes
        .iter()
        .find(|p| p.kind == RuntimeKind::Firecracker)
        .cloned();

    let checks = vec![
        check(
            "identity",
            "PARTIAL",
            "IntelligencePrincipalV2 and AgentIdentityEnvelopeV2 are minted at register. Public test — same user, same model, two agents, two receipt chains — is TARGET.",
        ),
        check(
            "contract",
            "PARTIAL",
            "compile_contract emits AgentContractV2 with digest, deny-default network, and denied ops. compile_openshell_projection emits the bundle. Push into a live OpenShell supervisor is TARGET.",
        ),
        check(
            "authority",
            "PARTIAL",
            "AuthorityRoot, GrantRef, attenuation, and revocation tombstones exist. Live demo — same prompt, revoke, deny without model restart — is TARGET as a single conformance command.",
        ),
        check(
            "pate",
            "PARTIAL",
            "PATE ATU wraps talk/tool/A2A admit and refuses stale generations. OPA remains inside OpenShell. Mismatch receipt (PATE allow, proxy deny) is TARGET.",
        ),
        check(
            "openshell",
            "TARGET",
            openshell
                .as_ref()
                .map(|p| p.detail.as_str())
                .unwrap_or("not_installed"),
        ),
        check(
            "runtime",
            "PARTIAL",
            "ConnectorRuntime catalog probes Firecracker, container, subprocess lab, and OpenShell. Identical contract semantics across Docker and Firecracker are TARGET.",
        ),
        check(
            "firecracker",
            if firecracker.as_ref().is_some_and(|p| p.ready) {
                "PARTIAL"
            } else {
                "TARGET"
            },
            firecracker
                .as_ref()
                .map(|p| p.detail.as_str())
                .unwrap_or("firecracker probe missing"),
        ),
        check(
            "cease",
            "PARTIAL",
            "kernel_cease voids ctx_tok, aborts in-flight LLM, writes CeaseReceiptV1, seals the memory epoch, stores the policy generation, and pauses a bound MicroCell. GET /runtime/cease-proof/:agent_pid scores the ten steps. Steps 5 and 10 use generation_is_live, the same check as assert_live_generation, and do not count a retry. Step 10 is present only when a continue carrying the ceased generation would be DENIED stale_generation. No model is called. The scripted OpenShell demo stays target.",
        ),
        check(
            "memory",
            "PARTIAL",
            "MemPacket, memory-sequence DNA, and MomentProof exist. After cease, capsule injection is refused while the live generation equals the sealed generation. Epoch-42 public demo is TARGET.",
        ),
        check(
            "consequence",
            "PARTIAL",
            "GET /api/v1/runtime/explain/:receipt_id walks a cease or IIA receipt and fills authority, PATE, W3C trace, and MomentProof context only when those rows exist. A single signed spine is TARGET.",
        ),
        check(
            "three_identities",
            "PARTIAL",
            "Operator JWT, SPIRE SVID, and intelligence id stay separate. When all three are present, explain stores a SHA-256 commitment and an Ed25519 SignedPayloadV2 over it from the platform key. That signature does not authorize the effect. OpenShell sandbox id is not an agent id.",
        ),
    ];

    json!({
        "schema": SCHEMA,
        "principle": "prove, do not claim",
        "doc": "platform/docs/arch/CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md",
        "ownership": ownership(),
        "runtimes": runtime_adapter::catalog(),
        "checks": checks,
        "production_gate": super::production_gate::live(),
        "backends": backend_view,
        "supply_chain": supply,
        "iam": {
            "controller": "JWT",
            "verify": "platform/server/src/auth/core.rs auth::verify_token",
            "algorithm_local": "HMAC-SHA256 via jsonwebtoken",
            "sso": "OIDC id_token verified against provider JWKS (RS256) for Okta, Google, Azure AD; GitHub uses OAuth2",
            "middleware": "auth_middleware requires Bearer JWT or cpk_live_* on /api/v1, including /runtime/ecosystem and /runtime/explain",
            "honesty": "A verified JWT is the operator. It is not the agent and it does not mint a grant.",
        },
        "commands": [
            "connectorctl govern backends",
            "GET /api/v1/runtime/backends",
            "connectorctl govern deploy-verify linux-kvm",
            "GET /api/v1/runtime/deploy-verify?profile=linux-kvm",
            "connectorctl govern ecosystem",
            "GET /api/v1/runtime/ecosystem",
            "connectorctl govern explain <receipt-id>",
            "GET /api/v1/runtime/explain/:receipt_id",
            "connectorctl govern cease-proof <agent-pid>",
            "GET /api/v1/runtime/cease-proof/:agent_pid"
        ],
        "honesty": "PASS is unused in this report until a check is enforced end to end and covered by a conformance test. PARTIAL means the mechanism exists. TARGET means specified and not finished.",
    })
}

fn check(id: &str, status: &str, detail: &str) -> Value {
    debug_assert!(status != "PASS" || id == "firecracker");
    json!({
        "id": id,
        "status": status,
        "detail": detail,
    })
}

/// Operator identity taken from a JWT `auth::verify_token` already accepted.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedOperator<'a> {
    pub sub: &'a str,
    pub jti: &'a str,
    pub role: &'a str,
}

/// Reconstruct one receipt from records already stored. Missing links stay absent.
pub fn explain(
    state: &crate::state::PlatformState,
    receipt_id: &str,
    operator: Option<VerifiedOperator<'_>>,
    traceparent: Option<&str>,
) -> Value {
    let cease = folder_get(state, crate::substrate::spend_cease::FOLDER_CEASE, receipt_id);
    let iia = folder_get(
        state,
        crate::kernel::agent_principal::IIA_RECEIPT_CHAIN_FOLDER,
        receipt_id,
    );
    let agent_pid = agent_for_receipt(state, cease.as_ref(), iia.as_ref());
    let latest = if agent_pid.is_empty() {
        None
    } else {
        folder_get(
            state,
            crate::substrate::spend_cease::FOLDER_CEASE,
            &format!("latest:{agent_pid}"),
        )
    };
    let seal = if agent_pid.is_empty() {
        None
    } else {
        folder_get(state, super::runtime_adapter::MEMORY_EPOCH_FOLDER, &agent_pid)
    };
    let policy = if agent_pid.is_empty() {
        None
    } else {
        folder_get(
            state,
            super::runtime_adapter::POLICY_GEN_FOLDER,
            &format!("latest:{agent_pid}"),
        )
    };
    let principal = if agent_pid.is_empty() {
        None
    } else {
        crate::kernel::agent_principal::load_principal(state, &agent_pid)
    };
    let intelligence_id = principal
        .as_ref()
        .and_then(|p| p.intelligence_id.clone())
        .or_else(|| {
            iia.as_ref()
                .and_then(|v| v.get("intelligence_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });
    let principal_id = principal
        .as_ref()
        .map(|p| p.principal_id.clone())
        .or_else(|| {
            iia.as_ref()
                .and_then(|v| v.get("principal_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });
    let task_id = iia
        .as_ref()
        .and_then(|row| row.get("task_id"))
        .or_else(|| cease.as_ref().and_then(|row| row.get("task_id")))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let bound = if agent_pid.is_empty() {
        BoundRecords::default()
    } else {
        load_bound(state, &agent_pid, task_id.as_deref())
    };
    let explain_join = bound.explain_join.clone();
    let fetched = crate::services::cell_spiffe::fetch_spire_x509();
    let operator_sub = operator.map(|op| op.sub);
    let mut explained = assemble_explain(
        receipt_id,
        cease.as_ref(),
        iia.as_ref(),
        principal_id.as_deref(),
        intelligence_id.as_deref(),
        principal.as_ref().map(|p| p.contract_digest_sha256.as_str()),
        latest.as_ref(),
        seal.as_ref(),
        policy.as_ref(),
        &crate::services::cell_spiffe::local_cell_spiffe_id(),
        fetched.spiffe_id.as_deref(),
        operator,
        traceparent,
        &bound,
    );
    if let Some(court) = court_sign_three_ids(
        state.signing_key.ed25519(),
        operator_sub.unwrap_or(""),
        fetched.spiffe_id.as_deref().unwrap_or(""),
        intelligence_id.as_deref().unwrap_or(""),
    ) {
        if let Some(slot) = explained.pointer_mut("/identities/binding/value") {
            if let Some(obj) = slot.as_object_mut() {
                obj.insert("court".to_string(), court);
            }
        }
    }
    if let Some(obj) = explained.as_object_mut() {
        let honesty = if explain_join == "receipt_task" { "task_keyed" } else { "PARTIAL" };
        obj.insert("explain_join".into(), json!(explain_join));
        obj.insert("explain_honesty".into(), json!(honesty));
    }
    explained
}

struct BoundRecords {
    authority: Option<Value>,
    pate: Option<Value>,
    otel: Option<Value>,
    mempacket: Option<Value>,
    mismatch: Option<Value>,
    explain_join: String,
}

impl Default for BoundRecords {
    fn default() -> Self {
        Self {
            authority: None,
            pate: None,
            otel: None,
            mempacket: None,
            mismatch: None,
            explain_join: "absent".into(),
        }
    }
}

fn load_bound(state: &crate::state::PlatformState, agent_pid: &str, task_id: Option<&str>) -> BoundRecords {
    let grants = crate::kernel::world_gateway::list_grants(state, Some(agent_pid));
    let aacr = folder_get(state, crate::kernel::aacr::INDEX_FOLDER, agent_pid);
    let task_pate = task_id.and_then(|id| folder_get(state, crate::substrate::pate::ATU_FOLDER, id));
    let latest_pate = folder_get(
        state,
        crate::substrate::pate::ATU_FOLDER,
        &format!("latest:{agent_pid}"),
    );
    let (pate, explain_join) = if task_pate.is_some() {
        (task_pate, "receipt_task".to_string())
    } else if latest_pate.is_some() {
        (latest_pate, "agent_latest".to_string())
    } else {
        (None, "absent".to_string())
    };
    let moment = pate
        .as_ref()
        .and_then(|p| p.get("moment_id"))
        .and_then(|v| v.as_str())
        .and_then(|id| folder_get(state, crate::substrate::agent_memory::moment::MOMENT_FOLDER, id));
    let otel = folder_get(state, "trace_context", &format!("agent:{agent_pid}"))
        .filter(|v| v.get("trace_id").and_then(|t| t.as_str()).is_some());
    let mismatch = task_id
        .and_then(|id| folder_get(state, crate::substrate::pate::MISMATCH_FOLDER, id))
        .or_else(|| {
            folder_get(
                state,
                crate::substrate::pate::MISMATCH_FOLDER,
                &format!("latest:{agent_pid}"),
            )
        });
    let authority = if grants.is_empty() && aacr.is_none() && moment.as_ref().and_then(|m| m.get("authority_root")).is_none() {
        None
    } else {
        Some(json!({
            "grant_count": grants.len(),
            "grants": grants.iter().take(8).map(|g| json!({
                "address": g.get("address"),
                "effect": g.get("effect"),
            })).collect::<Vec<_>>(),
            "aacr_head_digest": aacr.as_ref().and_then(|v| v.get("head_digest")).cloned(),
            "aacr_schema": crate::kernel::aacr::SCHEMA,
            "moment_authority_root": moment.as_ref().and_then(|m| m.get("authority_root")).cloned(),
        }))
    };
    let pate_view = pate.as_ref().map(|p| {
        json!({
            "schema": p.get("schema"),
            "task_id": p.get("task_id"),
            "verdict": p.get("verdict"),
            "action_digest": p.get("action_digest"),
            "outcome": p.get("outcome"),
            "broker_epoch": p.get("broker_epoch"),
            "moment_id": p.get("moment_id"),
            "standard": "Connector PATE AugmentedTaskUnit. OPA stays inside OpenShell.",
        })
    });
    let mempacket = moment.as_ref().and_then(|m| {
        m.get("current_context_root")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|root| {
                json!({
                    "moment_id": m.get("moment_id"),
                    "context_root": root,
                    "evidence_root": m.get("evidence_root"),
                    "standard": "MomentProof. This is the committed context root, not a separate evidence schema.",
                })
            })
    });
    BoundRecords {
        authority,
        pate: pate_view,
        otel,
        mempacket,
        mismatch,
        explain_join,
    }
}

fn agent_for_receipt(
    state: &crate::state::PlatformState,
    cease: Option<&Value>,
    iia: Option<&Value>,
) -> String {
    if let Some(pid) = cease.and_then(|v| v.get("agent_pid")).and_then(|p| p.as_str()) {
        if !pid.is_empty() {
            return pid.to_string();
        }
    }
    let principal_id = iia.and_then(|v| v.get("principal_id")).and_then(|p| p.as_str()).unwrap_or("");
    if principal_id.is_empty() {
        return String::new();
    }
    let Ok(es) = state.engine_store.lock() else {
        return String::new();
    };
    let Ok(keys) = es.folder_keys(crate::kernel::agent_principal::IIA_PRINCIPAL_FOLDER, None) else {
        return String::new();
    };
    for key in keys {
        let Some(row) = es
            .folder_get(crate::kernel::agent_principal::IIA_PRINCIPAL_FOLDER, &key)
            .ok()
            .flatten()
        else {
            continue;
        };
        if row.get("principal_id").and_then(|v| v.as_str()) == Some(principal_id) {
            return key;
        }
    }
    String::new()
}

/// Ten-step cease proof from records already stored. Steps 5 and 10 stay target:
/// this command does not replay an admit and does not ask a model to continue.
pub fn cease_proof(state: &crate::state::PlatformState, agent_pid: &str) -> Value {
    let latest = folder_get(
        state,
        crate::substrate::spend_cease::FOLDER_CEASE,
        &format!("latest:{agent_pid}"),
    );
    let seal = folder_get(state, super::runtime_adapter::MEMORY_EPOCH_FOLDER, agent_pid);
    let live = folder_get(
        state,
        crate::substrate::llm_context_broker::FOLDER,
        &format!("gen:{agent_pid}"),
    )
    .and_then(|v| v.get("generation").cloned())
    .map(|g| match g {
        Value::String(s) => s,
        other => other.to_string(),
    });
    let full = latest
        .as_ref()
        .and_then(|v| v.get("receipt_id"))
        .and_then(|v| v.as_str())
        .and_then(|id| folder_get(state, crate::substrate::spend_cease::FOLDER_CEASE, id));
    let hops_cancelled = full
        .as_ref()
        .and_then(|v| v.get("hops_cancelled"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let live_n = live.as_deref().and_then(|s| s.parse::<u64>().ok());
    let next = latest
        .as_ref()
        .and_then(|v| v.get("generation_id_next"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sealed = seal
        .as_ref()
        .and_then(|v| v.get("sealed_generation"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let injection_refused = !sealed.is_empty() && live.as_deref() == Some(sealed);
    assemble_cease_proof(
        agent_pid,
        latest.as_ref(),
        seal.as_ref(),
        injection_refused,
        next,
        hops_cancelled,
        live_n,
    )
}

pub fn assemble_cease_proof(
    agent_pid: &str,
    latest: Option<&Value>,
    seal: Option<&Value>,
    injection_refused: bool,
    generation_next: &str,
    hops_cancelled: u64,
    live_generation: Option<u64>,
) -> Value {
    let fanout = latest.and_then(|v| v.get("fanout"));
    let tunnels = fanout
        .and_then(|v| v.pointer("/openshell/tunnels"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tunnel_cut = matches!(
        tunnels,
        "policy_generation_reload_requested" | "sandbox_created_with_this_policy"
    );
    let pause = fanout.and_then(|v| v.get("firecracker_pause"));
    let paused = pause
        .and_then(|v| v.get("attempted"))
        .and_then(|v| v.as_bool())
        == Some(true);
    let ceased = latest
        .and_then(|v| v.get("generation_id_ceased"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let fence_denies = live_generation
        .is_some_and(|live| !ceased.is_empty() && !crate::substrate::spend_cease::generation_is_live(ceased, live));
    let steps = vec![
        proof_step(
            1,
            "effect_in_flight",
            if hops_cancelled > 0 { "present" } else { "absent" },
            if hops_cancelled > 0 {
                "Cease released reserved hops for the ceased generation."
            } else {
                "No reserved hop was released. Nothing in flight was recorded."
            },
        ),
        proof_step(
            2,
            "cease_invoked",
            if latest.and_then(|v| v.get("receipt_id")).and_then(|v| v.as_str()).is_some() { "present" } else { "absent" },
            "latest cease receipt",
        ),
        proof_step(
            3,
            "generation_incremented",
            if generation_next.is_empty() { "absent" } else { "present" },
            generation_next,
        ),
        proof_step(
            4,
            "context_stale",
            if !generation_next.is_empty() && seal.and_then(|v| v.get("sealed_generation")).and_then(|v| v.as_str()) == Some(generation_next) {
                "present"
            } else {
                "absent"
            },
            "sealed_generation equals generation_id_next",
        ),
        proof_step(
            5,
            "admit_refuses_stale_generation",
            if fence_denies { "present" } else if latest.is_some() { "absent" } else { "target" },
            if fence_denies {
                "spend_stale_generation: the ceased generation is not the live broker generation. Same check as assert_live_generation. This read does not count a retry."
            } else {
                "Fence would not deny. Need a ceased generation and a live generation that differ."
            },
        ),
        proof_step(
            6,
            "tunnel_cut",
            if tunnel_cut { "present" } else { "absent" },
            tunnels,
        ),
        proof_step(
            7,
            "runtime_paused",
            if paused { "present" } else { "absent" },
            pause.and_then(|v| v.get("result")).and_then(|v| v.as_str()).unwrap_or("no pause result"),
        ),
        proof_step(
            8,
            "memory_not_injected",
            if injection_refused { "present" } else { "absent" },
            "capsule injection refused while live generation equals sealed_generation",
        ),
        proof_step(
            9,
            "receipt_lists_fanout",
            if fanout.is_some() { "present" } else { "absent" },
            "CeaseReceipt latest row includes fanout",
        ),
        {
            let decision = crate::substrate::spend_cease::continue_after_cease(ceased, live_generation);
            let (status, detail) = match decision {
                crate::substrate::spend_cease::ContinueAfterCease::DeniedStaleGeneration => (
                    "present",
                    "DENIED stale_generation. A continue carrying the ceased generation is refused by generation_is_live. No model was called. This read does not count a retry.",
                ),
                crate::substrate::spend_cease::ContinueAfterCease::NotDenied => (
                    "absent",
                    "The ceased generation is still the live broker generation, so continue would not be denied.",
                ),
                crate::substrate::spend_cease::ContinueAfterCease::NotEvaluated => (
                    "target",
                    "Need generation_id_ceased and the live broker generation. This command does not ask a model to continue.",
                ),
            };
            proof_step(10, "continue_denied", status, detail)
        },
    ];
    let any_present = steps.iter().any(|s| s.get("status").and_then(|v| v.as_str()) == Some("present"));
    json!({
        "schema": "connector.cease_proof.v1",
        "agent_pid": agent_pid,
        "status": if any_present { "PARTIAL" } else { "TARGET" },
        "steps": steps,
        "honesty": "present means a stored record or the same generation_is_live check admit uses. target means this command did not run that step. PASS is not used.",
    })
}

fn identity_commitment(
    operator_sub: Option<&str>,
    spire_id: Option<&str>,
    intelligence_id: Option<&str>,
) -> Value {
    let Some(op) = operator_sub.filter(|s| !s.is_empty() && !s.contains('\n')) else {
        return link_absent("Need a verified JWT sub, a fetched SPIFFE ID, and an intelligence id.");
    };
    let Some(spiffe) = spire_id.filter(|s| s.starts_with("spiffe://") && !s.contains('\n')) else {
        return link_absent("A cell URI is not a SPIRE SVID, so the three ids are not committed.");
    };
    let Some(intel) = intelligence_id.filter(|s| !s.is_empty() && !s.contains('\n')) else {
        return link_absent("Need a verified JWT sub, a fetched SPIFFE ID, and an intelligence id.");
    };
    let raw = format!("{op}\n{spiffe}\n{intel}");
    let digest = hex::encode(sha2::Sha256::digest(raw.as_bytes()));
    link_present(json!({
        "digest_sha256": digest,
        "standard": "SHA-256",
        "fields": ["operator.sub", "workload.spiffe_id", "intelligence.id"],
        "honesty": "SHA-256 of the three ids. When court is present it is an Ed25519 SignedPayloadV2 over this digest. It does not authorize the effect.",
    }))
}

const COMMITMENT_SCHEMA: &str = "connector.identity_commitment.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IdentityCommitmentBody {
    schema: String,
    operator_sub: String,
    spiffe_id: String,
    intelligence_id: String,
    digest_sha256: String,
    authorizes: bool,
}

/// Ed25519 over the same three lines as `identity_commitment`. None when any id is missing.
/// The signed body sets `authorizes` to false. This is not the effect signature.
pub fn court_sign_three_ids(
    key: &SigningKey,
    operator_sub: &str,
    spiffe_id: &str,
    intelligence_id: &str,
) -> Option<Value> {
    if operator_sub.is_empty()
        || operator_sub.contains('\n')
        || !spiffe_id.starts_with("spiffe://")
        || spiffe_id.contains(char::is_whitespace)
        || intelligence_id.is_empty()
        || intelligence_id.contains('\n')
    {
        return None;
    }
    let digest = hex::encode(sha2::Sha256::digest(
        format!("{operator_sub}\n{spiffe_id}\n{intelligence_id}").as_bytes(),
    ));
    let body = IdentityCommitmentBody {
        schema: COMMITMENT_SCHEMA.into(),
        operator_sub: operator_sub.into(),
        spiffe_id: spiffe_id.into(),
        intelligence_id: intelligence_id.into(),
        digest_sha256: digest,
        authorizes: false,
    };
    let payload = sign_json_ed25519(key, &body).ok()?;
    if !verify_signed_payload_v2(&body, &payload) {
        return None;
    }
    Some(json!({
        "standard": "Ed25519",
        "tier": "Ed25519Court",
        "body": body,
        "payload": payload,
        "honesty": "Platform key signs the three-id commitment. Does not authorize the effect. IntelligenceReceiptV2 remains the effect signature.",
    }))
}

fn investigator_trace(traceparent: Option<&str>) -> Value {
    let Some(tp) = traceparent.map(str::trim).filter(|s| !s.is_empty()) else {
        return json!({
            "status": "absent",
            "standard": "W3C Trace Context",
            "detail": "no traceparent on this request. This is not the effect trace.",
        });
    };
    let parts: Vec<&str> = tp.split('-').collect();
    let ok = parts.len() == 4
        && parts[0].len() == 2
        && parts[0] != "ff"
        && parts[0].chars().all(|c| c.is_ascii_hexdigit())
        && w3c_id(parts[1], 32)
        && w3c_id(parts[2], 16)
        && parts[3].len() == 2
        && parts[3].chars().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return json!({
            "status": "absent",
            "standard": "W3C Trace Context",
            "detail": "malformed traceparent ignored",
        });
    }
    json!({
        "status": "present",
        "standard": "W3C Trace Context",
        "traceparent": tp,
        "trace_id": parts[1],
        "span_id": parts[2],
        "honesty": "This is the trace of the explain request, not the effect.",
    })
}

fn w3c_id(s: &str, n: usize) -> bool {
    s.len() == n && s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c != '0')
}

fn proof_step(n: u8, name: &str, status: &str, detail: &str) -> Value {
    json!({"n": n, "step": name, "status": status, "detail": detail})
}

fn folder_get(state: &crate::state::PlatformState, folder: &str, key: &str) -> Option<Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(folder, key).ok().flatten()
}

pub fn assemble_explain(
    receipt_id: &str,
    cease: Option<&Value>,
    iia: Option<&Value>,
    principal_id: Option<&str>,
    intelligence_id: Option<&str>,
    contract_digest: Option<&str>,
    latest_cease: Option<&Value>,
    memory_seal: Option<&Value>,
    policy: Option<&Value>,
    workload_spiffe: &str,
    spire_id: Option<&str>,
    operator: Option<VerifiedOperator<'_>>,
    traceparent: Option<&str>,
    bound: &BoundRecords,
) -> Value {
    let found = cease.is_some() || iia.is_some();
    let effect = iia.and_then(|v| v.get("effect_digest_sha256")).cloned();
    let signature = iia.and_then(|v| v.get("signature")).cloned();
    let signing_tier = iia.and_then(|v| v.get("signing_tier")).cloned();
    let fanout = latest_cease.and_then(|v| v.get("fanout")).cloned();
    let intelligence = intelligence_id.or(principal_id);
    let commitment = identity_commitment(operator.map(|op| op.sub), spire_id, intelligence);
    let investigator = investigator_trace(traceparent);
    let mismatch_present = bound.mismatch.is_some();
    let mismatch_step = json!({
        "step": "enforcement_mismatch",
        "status": if mismatch_present { "present" } else { "none" },
        "value": if mismatch_present { bound.mismatch.clone().unwrap_or(Value::Null) } else { Value::Null },
        "detail": if mismatch_present {
            "PATE admitted and a later controller denied. Deny wins."
        } else {
            "No PATE-allow then runtime-deny record for this agent."
        },
    });
    json!({
        "schema": "connector.explain.v1",
        "receipt_id": receipt_id,
        "found": found,
        "principle": "missing links are absent, not invented",
        "identities": {
            "operator": match operator {
                Some(op) => link_present(json!({
                    "sub": op.sub,
                    "jti": op.jti,
                    "role": op.role,
                    "verified_by": "auth::verify_token",
                    "standard": "JWT RFC 7519",
                })),
                None => link_absent("no verified JWT on this request. Operator IAM is auth::verify_token, not the agent id."),
            },
            "intelligence": match intelligence {
                Some(id) => link_present(json!(id)),
                None => link_absent("no IntelligencePrincipalV2 for this receipt"),
            },
            "workload": match spire_id {
                Some(id) => json!({
                    "status": "present",
                    "value": id,
                    "local_cell_uri": workload_spiffe,
                    "standard": "SPIFFE",
                    "controller": "SPIRE",
                    "command": "spire-agent api fetch x509 -socketPath $SPIFFE_ENDPOINT_SOCKET",
                    "detail": "Fetched from the SPIRE Workload API. This SPIFFE ID is not the agent.",
                }),
                None => json!({
                    "status": "partial",
                    "value": workload_spiffe,
                    "detail": "SPIFFE-shaped cell URI. Not a SPIRE SVID. Set SPIFFE_ENDPOINT_SOCKET and install spire-agent to fetch one.",
                }),
            },
            "binding": commitment,
        },
        "investigator_trace": investigator,
        "chain": [
            step("receipt", found, json!({"cease": cease.is_some(), "iia": iia.is_some()})),
            step("contract", contract_digest.is_some(), json!(contract_digest)),
            step("authority", bound.authority.is_some(), bound.authority.clone().unwrap_or(Value::Null)),
            step("pate", bound.pate.is_some(), bound.pate.clone().unwrap_or(Value::Null)),
            step("memory_epoch", memory_seal.is_some(), memory_seal.cloned().unwrap_or(Value::Null)),
            step("policy_bundle", policy.and_then(|p| p.get("projection")).is_some(), policy.and_then(|p| p.get("contract_digest_sha256")).cloned().unwrap_or(Value::Null)),
            step("runtime", fanout.is_some(), fanout.unwrap_or(Value::Null)),
            step("observed_effect", effect.is_some(), effect.unwrap_or(Value::Null)),
            step("otel_trace", bound.otel.is_some(), bound.otel.clone().unwrap_or(Value::Null)),
            step("signature", signature.is_some(), json!({"signing_tier": signing_tier, "signature": signature})),
            step("mempacket", bound.mempacket.is_some(), bound.mempacket.clone().unwrap_or(Value::Null)),
            mismatch_step,
        ],
        "honesty": "A step is present only when its record is in the store. MemPacket here is the MomentProof context root when a moment was minted. A cease receipt proves the generation fence and fan-out, not the world effect.",
    })
}

fn step(name: &str, present: bool, value: Value) -> Value {
    json!({
        "step": name,
        "status": if present { "present" } else { "absent" },
        "value": if present { value } else { Value::Null },
    })
}

fn link_present(value: Value) -> Value {
    json!({"status": "present", "value": value})
}

fn link_absent(detail: &str) -> Value {
    json!({"status": "absent", "detail": detail})
}

fn ownership() -> Value {
    json!([
        {"problem": "agent sandbox", "controller": "NVIDIA OpenShell", "connector": "compile AgentContractV2 and call the openshell CLI; do not own the supervisor", "status": "PARTIAL"},
        {"problem": "network and L7 policy", "controller": "OPA/Rego inside OpenShell", "connector": "policy file plus denied-by-policy log line; do not run opa eval", "status": "PARTIAL"},
        {"problem": "hardware isolation", "controller": "Firecracker + jailer", "connector": "select posture and lifecycle", "status": "PARTIAL"},
        {"problem": "workload identity", "controller": "SPIFFE/SPIRE", "connector": "fetch X.509 SVID id with spire-agent; do not issue SVIDs", "status": "PARTIAL"},
        {"problem": "operator identity", "controller": "OIDC / OAuth2 / JWT / SCIM / mTLS", "connector": "bind operator to the action; JWT is not the agent", "status": "HAVE"},
        {"problem": "telemetry", "controller": "OpenTelemetry", "connector": "bind trace id to the consequence", "status": "PARTIAL"},
        {"problem": "tool transport", "controller": "MCP", "connector": "PATE admit before transport", "status": "PARTIAL"},
        {"problem": "agent transport", "controller": "A2A", "connector": "PATE admit before transport", "status": "PARTIAL"},
        {"problem": "artifact signing", "controller": "Sigstore/cosign", "connector": "cosign verify-blob when blob and signature paths are set; verified is the exit code", "status": "PARTIAL"},
        {"problem": "evidence signature", "controller": "Ed25519", "connector": "SigningTierV2::Ed25519Court on receipts and on the three-id commitment; HMAC is lab; the commitment does not authorize", "status": "PARTIAL"},
        {"problem": "intelligence identity", "controller": "Connector", "connector": "AgentIdentityEnvelopeV2", "status": "HAVE"},
        {"problem": "authority", "controller": "Connector", "connector": "GrantRef, attenuation, tombstone", "status": "HAVE"},
        {"problem": "intent admission", "controller": "Connector PATE", "connector": "AugmentedTaskUnit over ActionBinding", "status": "HAVE"},
        {"problem": "governed memory", "controller": "Connector", "connector": "MemPacket + epoch seal", "status": "PARTIAL"},
        {"problem": "cross-layer revoke", "controller": "Connector Cease", "connector": "generation fan-out", "status": "PARTIAL"},
        {"problem": "reconstruction", "controller": "Connector", "connector": "bind AACR, MomentProof, IIA receipt", "status": "TARGET"}
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_never_marks_openshell_or_explain_as_pass() {
        let report = report();
        let checks = report.get("checks").and_then(|v| v.as_array()).unwrap();
        for c in checks {
            let id = c.get("id").and_then(|v| v.as_str()).unwrap();
            let status = c.get("status").and_then(|v| v.as_str()).unwrap();
            assert_ne!(status, "PASS", "{id} must not be PASS in the honest report");
            assert!(
                matches!(status, "PARTIAL" | "TARGET" | "HAVE"),
                "{id} has unexpected status {status}"
            );
        }
        let openshell = checks
            .iter()
            .find(|c| c.get("id").and_then(|v| v.as_str()) == Some("openshell"))
            .unwrap();
        assert_eq!(
            openshell.get("status").and_then(|v| v.as_str()),
            Some("TARGET")
        );
        let explain = checks
            .iter()
            .find(|c| c.get("id").and_then(|v| v.as_str()) == Some("consequence"))
            .unwrap();
        assert_eq!(
            explain.get("status").and_then(|v| v.as_str()),
            Some("PARTIAL")
        );
    }

    #[test]
    fn ownership_keeps_opa_and_jwt_in_their_lanes() {
        let rows = ownership();
        let rows = rows.as_array().unwrap();
        let opa = rows
            .iter()
            .find(|r| r.get("controller").and_then(|v| v.as_str()) == Some("OPA/Rego inside OpenShell"))
            .unwrap();
        assert_eq!(opa.get("status").and_then(|v| v.as_str()), Some("PARTIAL"));
        let connector = opa.get("connector").and_then(|v| v.as_str()).unwrap_or("");
        assert!(connector.contains("do not run opa eval"));
        let jwt = rows
            .iter()
            .find(|r| {
                r.get("problem").and_then(|v| v.as_str()) == Some("operator identity")
            })
            .unwrap();
        assert_eq!(jwt.get("status").and_then(|v| v.as_str()), Some("HAVE"));
    }

    #[test]
    fn explain_marks_missing_spine_links_absent() {
        let cease = serde_json::json!({
            "receipt_id": "cease_1",
            "agent_pid": "agent-1",
            "generation_id_next": "2"
        });
        let explained = assemble_explain(
            "cease_1",
            Some(&cease),
            None,
            Some("cnktr:agent:1"),
            Some("cnktr:intelligence:abc"),
            Some("digest"),
            None,
            None,
            None,
            "spiffe://connector.local/cell/cell_local",
            None,
            None,
            None,
            &BoundRecords::default(),
        );
        assert_eq!(explained.get("found").and_then(|v| v.as_bool()), Some(true));
        let chain = explained.get("chain").and_then(|v| v.as_array()).unwrap();
        let status = |name: &str| {
            chain
                .iter()
                .find(|s| s.get("step").and_then(|v| v.as_str()) == Some(name))
                .and_then(|s| s.get("status").and_then(|v| v.as_str()))
                .unwrap()
                .to_string()
        };
        assert_eq!(status("receipt"), "present");
        assert_eq!(status("contract"), "present");
        assert_eq!(status("authority"), "absent");
        assert_eq!(status("pate"), "absent");
        assert_eq!(status("otel_trace"), "absent");
        assert_eq!(status("mempacket"), "absent");
        assert_eq!(status("observed_effect"), "absent");
        let workload = explained.pointer("/identities/workload/status").and_then(|v| v.as_str());
        assert_eq!(workload, Some("partial"));
        assert_eq!(
            explained.pointer("/identities/workload/value").and_then(|v| v.as_str()),
            Some("spiffe://connector.local/cell/cell_local")
        );
        assert_eq!(
            explained.pointer("/identities/operator/status").and_then(|v| v.as_str()),
            Some("absent")
        );
    }

    #[test]
    fn explain_operator_is_the_verified_jwt_subject() {
        let explained = assemble_explain(
            "cease_1",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "spiffe://connector.local/cell/cell_local",
            None,
            Some(VerifiedOperator {
                sub: "user-7",
                jti: "jti-9",
                role: "operator",
            }),
            None,
            &BoundRecords::default(),
        );
        assert_eq!(
            explained.pointer("/identities/operator/status").and_then(|v| v.as_str()),
            Some("present")
        );
        assert_eq!(
            explained.pointer("/identities/operator/value/sub").and_then(|v| v.as_str()),
            Some("user-7")
        );
        assert_eq!(
            explained.pointer("/identities/operator/value/verified_by").and_then(|v| v.as_str()),
            Some("auth::verify_token")
        );
    }

    #[test]
    fn explain_commits_three_ids_and_separates_the_request_trace() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let explained = assemble_explain(
            "cease_1",
            None,
            None,
            None,
            Some("cnktr:intelligence:abc"),
            None,
            None,
            None,
            None,
            "spiffe://connector.local/cell/cell_local",
            Some("spiffe://example.org/ns/default/sa/default"),
            Some(VerifiedOperator {
                sub: "user-7",
                jti: "jti-9",
                role: "operator",
            }),
            Some(tp),
            &BoundRecords::default(),
        );
        let raw = "user-7\nspiffe://example.org/ns/default/sa/default\ncnktr:intelligence:abc";
        let expect = hex::encode(sha2::Sha256::digest(raw.as_bytes()));
        assert_eq!(
            explained.pointer("/identities/binding/status").and_then(|v| v.as_str()),
            Some("present")
        );
        assert_eq!(
            explained.pointer("/identities/binding/value/digest_sha256").and_then(|v| v.as_str()),
            Some(expect.as_str())
        );
        assert_eq!(
            explained.pointer("/investigator_trace/trace_id").and_then(|v| v.as_str()),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(
            explained.pointer("/investigator_trace/honesty").and_then(|v| v.as_str()),
            Some("This is the trace of the explain request, not the effect.")
        );
        let chain = explained.get("chain").and_then(|v| v.as_array()).unwrap();
        let otel = chain.iter().find(|s| s.get("step").and_then(|v| v.as_str()) == Some("otel_trace")).unwrap();
        assert_eq!(otel.get("status").and_then(|v| v.as_str()), Some("absent"));
        assert_eq!(
            investigator_trace(Some("00-00000000000000000000000000000000-0000000000000000-01"))
                .get("status").and_then(|v| v.as_str()),
            Some("absent")
        );
    }

    #[test]
    fn three_id_commitment_is_ed25519_and_does_not_authorize() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let spiffe = "spiffe://example.org/ns/default/sa/default";
        let intel = "cnktr:intelligence:abc";
        let signed = court_sign_three_ids(&key, "user-7", spiffe, intel).expect("three ids");
        assert_eq!(signed["tier"], "Ed25519Court");
        assert_eq!(signed["standard"], "Ed25519");
        let body: IdentityCommitmentBody =
            serde_json::from_value(signed["body"].clone()).expect("body");
        let payload: connector_trust::SignedPayloadV2 =
            serde_json::from_value(signed["payload"].clone()).expect("payload");
        assert!(!body.authorizes);
        let raw = format!("user-7\n{spiffe}\n{intel}");
        assert_eq!(body.digest_sha256, hex::encode(sha2::Sha256::digest(raw.as_bytes())));
        assert!(verify_signed_payload_v2(&body, &payload));
        let mut tampered = body.clone();
        tampered.authorizes = true;
        assert!(!verify_signed_payload_v2(&tampered, &payload));
        assert!(court_sign_three_ids(&key, "user-7", "not-a-spiffe-id", intel).is_none());
        assert!(court_sign_three_ids(&key, "user\n7", spiffe, intel).is_none());
    }

    #[test]
    fn explain_workload_is_present_only_for_a_fetched_spiffe_id() {
        let explained = assemble_explain(
            "cease_1",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "spiffe://connector.local/cell/cell_local",
            Some("spiffe://example.org/ns/default/sa/default"),
            None,
            None,
            &BoundRecords::default(),
        );
        assert_eq!(
            explained.pointer("/identities/workload/status").and_then(|v| v.as_str()),
            Some("present")
        );
        assert_eq!(
            explained.pointer("/identities/workload/value").and_then(|v| v.as_str()),
            Some("spiffe://example.org/ns/default/sa/default")
        );
        assert_eq!(
            explained.pointer("/identities/workload/local_cell_uri").and_then(|v| v.as_str()),
            Some("spiffe://connector.local/cell/cell_local")
        );
    }

    #[test]
    fn explain_fills_authority_pate_trace_and_mismatch_when_records_exist() {
        let authority = json!({"grant_count": 1, "grants": [{"address": "https://api.example", "effect": "allow"}]});
        let pate = json!({"task_id": "pate_1", "verdict": "Proceed"});
        let otel = json!({"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "standard": "W3C Trace Context"});
        let mem = json!({"moment_id": "M-1", "context_root": "abc"});
        let mismatch = json!({"schema": "connector.policy_mismatch.v1", "deny_wins": true, "openshell_opa": false});
        let bound = BoundRecords {
            authority: Some(authority),
            pate: Some(pate),
            otel: Some(otel),
            mempacket: Some(mem),
            mismatch: Some(mismatch),
            explain_join: "receipt_task".into(),
        };
        let explained = assemble_explain(
            "cease_1",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "spiffe://connector.local/cell/cell_local",
            None,
            None,
            None,
            &bound,
        );
        let chain = explained.get("chain").and_then(|v| v.as_array()).unwrap();
        let status = |name: &str| {
            chain
                .iter()
                .find(|s| s.get("step").and_then(|v| v.as_str()) == Some(name))
                .and_then(|s| s.get("status").and_then(|v| v.as_str()))
                .unwrap()
                .to_string()
        };
        assert_eq!(status("authority"), "present");
        assert_eq!(status("pate"), "present");
        assert_eq!(status("otel_trace"), "present");
        assert_eq!(status("mempacket"), "present");
        assert_eq!(status("enforcement_mismatch"), "present");
        assert_eq!(
            explained.pointer("/chain").and_then(|v| v.as_array()).unwrap()
                .iter()
                .find(|s| s.get("step").and_then(|v| v.as_str()) == Some("enforcement_mismatch"))
                .and_then(|s| s.pointer("/value/openshell_opa"))
                .and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn cease_proof_never_passes_and_leaves_replay_steps_target() {
        let latest = json!({
            "receipt_id": "cease_1",
            "generation_id_next": "2",
            "fanout": {
                "openshell": {"tunnels": "not_cut_no_supervisor_session"},
                "firecracker_pause": {"attempted": false, "result": "no_microcell"}
            }
        });
        let seal = json!({"sealed_generation": "2"});
        let proof = assemble_cease_proof("agent-1", Some(&latest), Some(&seal), true, "2", 0, None);
        assert_ne!(proof.get("status").and_then(|v| v.as_str()), Some("PASS"));
        assert_eq!(proof.get("status").and_then(|v| v.as_str()), Some("PARTIAL"));
        let steps = proof.get("steps").and_then(|v| v.as_array()).unwrap();
        let status = |name: &str| {
            steps.iter().find(|s| s.get("step").and_then(|v| v.as_str()) == Some(name))
                .and_then(|s| s.get("status").and_then(|v| v.as_str()))
                .unwrap()
        };
        assert_eq!(status("cease_invoked"), "present");
        assert_eq!(status("generation_incremented"), "present");
        assert_eq!(status("context_stale"), "present");
        assert_eq!(status("memory_not_injected"), "present");
        assert_eq!(status("receipt_lists_fanout"), "present");
        assert_eq!(status("tunnel_cut"), "absent");
        assert_eq!(status("admit_refuses_stale_generation"), "absent");
        assert_eq!(status("continue_denied"), "target");
        assert_eq!(status("effect_in_flight"), "absent");
    }

    #[test]
    fn cease_proof_uses_the_live_generation_fence() {
        let latest = json!({
            "receipt_id": "cease_1",
            "generation_id_ceased": "1",
            "generation_id_next": "2",
            "fanout": {}
        });
        let proof = assemble_cease_proof("agent-1", Some(&latest), None, false, "2", 2, Some(2));
        let steps = proof.get("steps").and_then(|v| v.as_array()).unwrap();
        let status = |name: &str| {
            steps.iter().find(|s| s.get("step").and_then(|v| v.as_str()) == Some(name))
                .and_then(|s| s.get("status").and_then(|v| v.as_str()))
                .unwrap()
        };
        assert_eq!(status("effect_in_flight"), "present");
        assert_eq!(status("admit_refuses_stale_generation"), "present");
        assert!(crate::substrate::spend_cease::generation_is_live("2", 2));
        assert!(!crate::substrate::spend_cease::generation_is_live("1", 2));
        assert_eq!(status("continue_denied"), "present");
        let detail = steps
            .iter()
            .find(|s| s.get("step").and_then(|v| v.as_str()) == Some("continue_denied"))
            .and_then(|s| s.get("detail").and_then(|v| v.as_str()))
            .unwrap_or("");
        assert!(detail.contains("DENIED stale_generation"));
        assert!(detail.contains("No model was called"));
        assert_eq!(
            crate::substrate::spend_cease::continue_after_cease("2", Some(2)),
            crate::substrate::spend_cease::ContinueAfterCease::NotDenied
        );
        let still = json!({
            "receipt_id": "cease_1",
            "generation_id_ceased": "2",
            "generation_id_next": "2",
        });
        let still_live = assemble_cease_proof("agent-1", Some(&still), None, false, "2", 0, Some(2));
        let still_steps = still_live.get("steps").and_then(|v| v.as_array()).unwrap();
        let still_status = still_steps
            .iter()
            .find(|s| s.get("step").and_then(|v| v.as_str()) == Some("continue_denied"))
            .and_then(|s| s.get("status").and_then(|v| v.as_str()));
        assert_eq!(still_status, Some("absent"));
        assert_ne!(proof.get("status").and_then(|v| v.as_str()), Some("PASS"));
        assert_ne!(still_live.get("status").and_then(|v| v.as_str()), Some("PASS"));
    }

    #[test]
    fn explain_unknown_receipt_is_not_found() {
        let explained = assemble_explain("missing", None, None, None, None, None, None, None, None, "spiffe://connector.local/cell/cell_local", None, None, None, &BoundRecords::default());
        assert_eq!(explained.get("found").and_then(|v| v.as_bool()), Some(false));
    }
}
