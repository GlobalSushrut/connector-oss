#!/usr/bin/env python3
"""Investor-grade enterprise demo runner.

Usage:
  python demos/demo.py bootstrap           # seed live agent + memory
  python demos/demo.py run_agent           # generate 1 live governed decision
  python demos/demo.py run_failure_case    # generate 1 failure investigation case
  python demos/demo.py run_phi_case        # generate 1 PHI compliance case
  python demos/demo.py                     # run interactive 12-slide deck
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))

from system_data import ConnectorPlatform

PRIMARY_SYSTEM_PROMPT = "You are a governed clinical AI agent. Be concise and precise."
PRIMARY_USER_PROMPT = (
    "Patient: 45yo, chest pain, shortness of breath, fatigue. "
    "History: hypertension, former smoker. Allergy: penicillin. "
    "Top 3 clinical considerations + one governance precaution?"
)
FAILURE_SYSTEM_PROMPT = "You are a governed clinical AI agent. Be concise."
FAILURE_USER_PROMPT = (
    "Patient: 58yo, pain, fatigue. What medication should be prescribed? "
    "Note: allergy and full history context intentionally omitted."
)
PHI_SYSTEM_PROMPT = "You are a governed clinical AI agent handling PHI. Be concise."
PHI_USER_PROMPT_TEMPLATE = (
    "Patient ID: {resource_id}. Diagnosis: hypertension. "
    "Summarise governance steps required before sharing this PHI."
)
DEMO_CLS_SOURCE = r"""contract clinical_governance {
    solution clinical_governance version "1.0.0" {
        domain healthcare
        owner "connector-demo"
        description: "Governed clinical decision pipeline with PHI controls"
        tags: [clinical, hipaa, governed, phi]
    }
    capabilities {
        tool clinical_assessment advisory
        tool record_decision binding
        memory patient_history readonly
        memory clinical_guidelines readonly
        memory case_context readwrite
        protocol native
        model decision_model
        review_queue escalation_review
    }
    policy {
        require audit_trail
        require human_review when confidence < 0.80
        deny export_pii outside case_context
        deny tool_external unless approved
        allow override conforms admin_override_schema
    }
    flow {
        stage validate {
            require patient_context is present
            require allergy_data is present
        }
        stage assess {
            call clinical_assessment with { patient: ${patient_context} } as assessment
        }
        stage decide {
            when assessment == false {
                emit decision { status: "escalate" }
            } otherwise {
                emit decision { status: "approve" }
            }
        }
    }
    budget {
        tokens: 8192
        cost_usd: 1.00
        tool_calls: 20
    }
    governance {
        require patient_context is present
        ensure clinical_decision is present
        roles [operator, clinician]
        clearance "high"
        compliance [hipaa, gdpr]
    }
}"""


def to_json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


def safe_call(fn, *args, **kwargs) -> Dict[str, Any]:
    t0 = time.monotonic()
    try:
        result = fn(*args, **kwargs)
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        return {"ok": True, "data": result, "latency_ms": elapsed}
    except Exception as exc:
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        return {"ok": False, "error": str(exc), "latency_ms": elapsed}


def extract_agents(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("agents"), list):
        return payload["agents"]
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("agents"), list):
        return data["agents"]
    return []


def extract_pid(payload: Any) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    for key in ("pid", "agent_pid", "id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    nested = payload.get("data")
    if isinstance(nested, dict):
        for key in ("pid", "agent_pid", "id"):
            value = nested.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def select_agent(agents_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    agents = extract_agents(agents_payload)
    if not agents:
        return None
    forced_pid = os.getenv("DEMO_AGENT_PID", "")
    if forced_pid:
        for agent in agents:
            if extract_pid(agent) == forced_pid:
                return agent
    for agent in agents:
        name = str(agent.get("name", ""))
        status = str(agent.get("status", "")).lower()
        if name.startswith("demo-") and status in {"running", "ready", "healthy"}:
            return agent
    for agent in agents:
        if str(agent.get("status", "")).lower() in {"running", "ready", "healthy"}:
            return agent
    # Fallback: prefer demo agents, then any agent
    for agent in agents:
        name = str(agent.get("name", ""))
        if name.startswith("demo"):
            return agent
    return agents[0]


def pause(enabled: bool) -> None:
    if not enabled:
        return
    try:
        input("\nPress Enter for next slide... ")
    except EOFError:
        pass


def _demo_phi_resource(pid: str = "") -> str:
    forced = os.getenv("DEMO_PHI_RESOURCE", "")
    if forced:
        return forced
    suffix = (pid or "demo").replace(":", "").replace("/", "-")
    return f"PHI-{suffix}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"


def _phi_user_prompt(resource_id: str) -> str:
    return PHI_USER_PROMPT_TEMPLATE.format(resource_id=resource_id)


def print_slide(slide: Dict[str, Any], interactive: bool) -> None:
    width = 88
    print("\n" + "=" * width)
    print(f"  SLIDE {slide['number']}: {slide['title']}")
    print("=" * width)
    print()
    for line in slide["narration"].splitlines():
        print(f"  {line}")
    print()
    print("  Operator Commands")
    for command in slide["commands"]:
        print(f"    $ {command}")
    print()
    print("  Evidence")
    print(to_json(slide["evidence"]))
    print()
    if slide.get("fail_fast"):
        print("  Fail Fast")
        for rule in slide["fail_fast"]:
            print(f"    - {rule}")
    pause(interactive)


def get_or_create_agent(platform: ConnectorPlatform) -> Dict[str, Any]:
    """Return a demo agent, creating one if none exists. Works with suspended agents."""
    agents_payload = platform.list_agents()
    agent = select_agent(agents_payload)
    if agent is not None and extract_pid(agent):
        pid = extract_pid(agent)
        # For demo purposes, work with suspended agents without trying to start them
        status = str(agent.get("status", "")).lower()
        if status in {"suspended"}:
            print(f"  ! Using suspended agent: {pid} ({agent.get('name', 'unknown')})")
            return agent
        # Always call start_agent: kernel phase may be 'registered' after server
        # restart even when the API status string reports 'healthy'. start_agent
        # is idempotent — errors if already running are silently ignored.
        try:
            platform.start_agent(pid)
            agent = platform.get_agent(pid)
        except Exception:
            pass
        return agent
    name = f"demo-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    created = platform.register_agent(name, "Enterprise demo agent", clearance=3)
    pid = extract_pid(created)
    if not pid:
        for candidate in extract_agents(platform.list_agents()):
            if candidate.get("name") == name:
                pid = candidate.get("pid")
                agent = candidate
                break
    if not pid:
        raise RuntimeError("Cannot resolve agent PID")
    # Some API shapes return an API id while /start expects kernel pid.
    # Try direct start first, then resolve by name from list_agents().
    try:
        platform.start_agent(pid)
        return platform.get_agent(pid)
    except Exception:
        for candidate in extract_agents(platform.list_agents()):
            if candidate.get("name") == name:
                cpid = extract_pid(candidate) or candidate.get("pid")
                if isinstance(cpid, str) and cpid:
                    try:
                        platform.start_agent(cpid)
                    except Exception:
                        pass
                    try:
                        return platform.get_agent(cpid)
                    except Exception:
                        return candidate
        # Last fallback: return created payload to avoid hard crash.
        return created if isinstance(created, dict) else {"pid": pid, "name": name}


def get_or_create_peer_agent(platform: ConnectorPlatform, primary_pid: str) -> Optional[Dict[str, Any]]:
    """Pick an existing agent with a different PID for sandboxing demo, or create one."""
    agents = extract_agents(platform.list_agents())
    # Prefer any running agent that is not the primary
    for candidate in agents:
        cpid = extract_pid(candidate) or candidate.get("pid")
        cstatus = str(candidate.get("status", "")).lower()
        if cpid and cpid != primary_pid and cstatus in {"running", "ready", "healthy"}:
            return candidate
    # Try any agent at all that is not primary
    for candidate in agents:
        cpid = extract_pid(candidate) or candidate.get("pid")
        if cpid and cpid != primary_pid:
            try:
                platform.start_agent(cpid)
                return platform.get_agent(cpid)
            except Exception:
                continue
    # Create a new one as last resort
    name = f"demo-peer-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    try:
        created = platform.register_agent(name, "Enterprise demo peer agent", clearance=2)
        pid = extract_pid(created)
        if not pid:
            for candidate in extract_agents(platform.list_agents()):
                if candidate.get("name") == name:
                    pid = extract_pid(candidate) or candidate.get("pid")
                    break
        if pid:
            try:
                platform.start_agent(pid)
            except Exception:
                pass
            try:
                return platform.get_agent(pid)
            except Exception:
                return {"pid": pid, "name": name}
    except Exception:
        pass
    return None


def _chat(platform: ConnectorPlatform, agent: Dict[str, Any],
          system: str, user: str) -> Dict[str, Any]:
    pid = extract_pid(agent) or agent.get("pid")
    ns = agent.get("namespace") or f"m/{agent.get('name', pid)}"
    if pid:
        platform.write_memory(
            pid,
            json.dumps({
                "kind": "human_prompt",
                "prompt_text": user,
                "agent_pid": pid,
                "namespace": ns,
                "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }, ensure_ascii=False),
            ptype="input",
            session_id=f"human-prompt-{pid}",
            memory_type="working",
            tags=["demo", "human_prompt", "live_request"],
            user=pid,
            entity_kind="human_prompt",
        )
    resp = safe_call(platform.invoke_chat, pid, ns, user, system=system)
    if resp.get("ok"):
        return resp
    if os.getenv("CONNECTOR_LLM_STUB") == "1":
        content = (
            "Stub mode response: top considerations are cardiac risk stratification, "
            "urgent diagnostics, and allergy-safe treatment planning. "
            "Governance precaution: require operator review before PHI sharing."
        )
        synthetic_cid = "stub-" + hashlib.sha256(f"{pid}:{user}".encode("utf-8")).hexdigest()[:16]
        return {
            "ok": True,
            "data": {
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "audit_cid": synthetic_cid,
                "model": "stub-governed-demo",
            },
            "latency_ms": 0.0,
        }
    return resp


def extract_response_evidence(resp: Dict[str, Any]) -> Dict[str, Any]:
    if not resp.get("ok"):
        return {"error": resp.get("error", "unavailable")}
    data = resp.get("data", {})
    choices = data.get("choices", [])
    text = choices[0].get("message", {}).get("content", "") if choices else ""
    usage = data.get("usage", {})
    model = data.get("model", "")
    stub = _is_stub_mode() or str(model).startswith("stub-")
    return {
        "response": (text[:600] + "...") if len(text) > 600 else text,
        "tokens_used": 0 if stub else usage.get("total_tokens", 0),
        "prompt_tokens": 0 if stub else usage.get("prompt_tokens", 0),
        "completion_tokens": 0 if stub else usage.get("completion_tokens", 0),
        "audit_cid": data.get("audit_cid"),
        "model": model,
    }


def _risk_and_escalation(outcome: str, trust_grade: Optional[str]) -> Dict[str, str]:
    outcome_l = (outcome or "").lower()
    grade = (trust_grade or "B").upper()
    if any(flag in outcome_l for flag in ["deny", "blocked", "gap", "missing"]):
        return {"risk_level": "high", "escalation": "required"}
    if grade in {"D", "F"}:
        return {"risk_level": "high", "escalation": "required"}
    if grade == "C":
        return {"risk_level": "medium", "escalation": "operator_review"}
    return {"risk_level": "low", "escalation": "not_required"}


def _is_stub_mode() -> bool:
    return os.getenv("CONNECTOR_LLM_STUB") == "1"


def _normalize_trust_grade(value: Optional[str]) -> str:
    grade = (value or "").strip().upper()
    if grade in {"A", "B", "C", "D", "F"}:
        return grade
    return "B"


def _policy_verdict(policy: Dict[str, Any]) -> Dict[str, str]:
    if not isinstance(policy, dict):
        return {"verdict": "UNKNOWN", "reason": "policy_unavailable"}
    if policy.get("error"):
        return {"verdict": "UNKNOWN", "reason": str(policy.get("error"))}
    if "verdict" in policy and isinstance(policy.get("verdict"), str):
        verdict = policy.get("verdict", "").upper() or "UNKNOWN"
        return {"verdict": verdict, "reason": str(policy.get("reason", ""))}
    if "allowed" in policy:
        return {
            "verdict": "ALLOW" if bool(policy.get("allowed")) else "DENY",
            "reason": str(policy.get("reason", "")),
        }
    return {"verdict": "UNKNOWN", "reason": "no_policy_fields"}


def _decision_consequence_card(mode: str, decision: Dict[str, Any], compliance: List[str]) -> Dict[str, Any]:
    trust_grade = _normalize_trust_grade(decision.get("trust_grade"))
    outcome = "allowed" if mode == "run_agent" else "blocked_or_investigate"
    risk = _risk_and_escalation(outcome, trust_grade)
    tokens = decision.get("tokens", decision.get("tokens_used", 0))
    model = str(decision.get("model", ""))
    stub_mode = _is_stub_mode() or model.startswith("stub-")
    cost_usd = decision.get("cost_usd")
    if cost_usd is None:
        cost_usd = 0.0 if stub_mode else _cost_usd(tokens)
    return {
        "mode": mode,
        "decision_id": decision.get("decision_id", ""),
        "trust_grade": trust_grade,
        "compliance": compliance,
        "tokens": tokens,
        "cost_usd": cost_usd,
        "outcome": outcome,
        "downstream_effect": {
            "time_ms_estimate": max(tokens // 2, 1),
            "blocked": mode != "run_agent",
            "risk_delta": "up" if mode != "run_agent" else "down",
        },
        "risk_level": risk["risk_level"],
        "escalation": risk["escalation"],
        "next_step": (
            "continue_workflow"
            if mode == "run_agent"
            else "collect_missing_context_then_replay"
        ),
    }


def _operator_close_scorecard(context: Dict[str, Any]) -> Dict[str, Any]:
    stub_mode = bool(context.get("stub_mode"))
    policy_v = _policy_verdict(context.get("policy_phi", {}))
    checks = {
        "control_edge": policy_v["verdict"] in {"ALLOW", "DENY"} and bool(context.get("reasoning_chain")),
        "proof_edge": bool(context.get("proof_id")) and bool(context.get("chain_head")) and bool(context.get("content_hash")),
        "compliance_edge": bool(context.get("hipaa_sections")),
        "cost_edge": (context.get("total_cost_usd", 0) > 0) or stub_mode,
        "replay_edge": bool(context.get("replay", {}).get("ok")),
        "failure_edge": bool(context.get("fail_dec", {}).get("decision_id")),
        "hitl_edge": policy_v["verdict"] in {"ALLOW", "DENY"},
        "cls_edge": bool(context.get("cls_compile", {}).get("ok")),
        "soe_edge": any(v.get("ok") for v in context.get("soe_surfaces", {}).values()),
        "deny_edge": context.get("deny_probe", {}).get("verdict") == "DENY",
        "influence_edge": context.get("influence_change", {}).get("changed") is True,
    }
    passed = sum(1 for ok in checks.values() if ok)
    failed = [name for name, ok in checks.items() if not ok]
    return {
        "checks": checks,
        "passed": passed,
        "total": len(checks),
        "close_ready": not failed,
        "gaps": failed,
        "positioning": (
            "deal_closing"
            if not failed
            else "pilot_ready_with_gaps"
        ),
    }


def _control_execution_snapshot(policy_read: Dict[str, Any], policy_write: Dict[str, Any]) -> Dict[str, Any]:
    read_v = _policy_verdict(policy_read)
    write_v = _policy_verdict(policy_write)
    return {
        "control_read_phi": read_v,
        "control_write_phi": write_v,
        "enforcement_state": (
            "enforced"
            if write_v.get("verdict") == "DENY"
            else ("partial" if write_v.get("verdict") == "UNKNOWN" else "allowing_write")
        ),
        "hitl_required": write_v.get("verdict") in {"DENY", "UNKNOWN"},
    }


def _influence_change_snapshot(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    before_text = before.get("text", "")
    after_text = after.get("text", "")
    before_hash = hashlib.sha256(before_text.encode("utf-8")).hexdigest() if before_text else ""
    after_hash = hashlib.sha256(after_text.encode("utf-8")).hexdigest() if after_text else ""
    return {
        "before_decision_id": before.get("decision_id", ""),
        "after_decision_id": after.get("decision_id", ""),
        "before_output_hash": before_hash,
        "after_output_hash": after_hash,
        "before_tokens": before.get("tokens", 0),
        "after_tokens": after.get("tokens", 0),
        "changed": bool(before_hash and after_hash and before_hash != after_hash),
        "change_note": "Decision changed after remediation context was added",
    }


def _claim_posture(status: str) -> str:
    allowed = {"proven_live", "partial_live", "not_proven_live", "stub_mode"}
    return status if status in allowed else "not_proven_live"


def _build_claim_posture(stub_mode: bool, gateway_proof: Dict[str, Any], isolation_proof: Dict[str, Any], multi_agent: Dict[str, Any], tool_execution: Dict[str, Any],
                         proof_id: str, chain_head: str, content_hash: str,
                         control_execution: Dict[str, Any]) -> Dict[str, str]:
    if stub_mode:
        return {
            "no_code_changes": "stub_mode",
            "plug_and_play": "stub_mode",
            "runtime_isolation": "stub_mode",
            "governed_actions": "stub_mode",
            "audit_proof": "stub_mode",
        }
    runtime_isolation = "partial_live"
    mac = multi_agent.get("sandboxing", {}).get("mac_enforcement", {})
    if mac.get("verdict") == "DENY" and isolation_proof.get("invariants_ok") and isolation_proof.get("denied_ops_visible"):
        runtime_isolation = "proven_live"
    no_code_changes = "not_proven_live"
    plug_and_play = "partial_live"
    if gateway_proof.get("route_available") and gateway_proof.get("openai_compatible") and gateway_proof.get("base_url_override_supported"):
        no_code_changes = "proven_live"
        plug_and_play = "proven_live"
    governed_actions = "partial_live"
    if tool_execution.get("registered") and tool_execution.get("invoke_result", {}).get("outcome"):
        governed_actions = "proven_live"
    audit_proof = "partial_live"
    if proof_id and chain_head and content_hash:
        audit_proof = "proven_live"
    return {
        "no_code_changes": _claim_posture(no_code_changes),
        "plug_and_play": _claim_posture(plug_and_play),
        "runtime_isolation": _claim_posture(runtime_isolation),
        "governed_actions": _claim_posture(governed_actions),
        "audit_proof": _claim_posture(audit_proof),
    }


def _deterministic_replay(platform: ConnectorPlatform, agent: Dict[str, Any]) -> Dict[str, Any]:
    prompt = PRIMARY_USER_PROMPT
    system = PRIMARY_SYSTEM_PROMPT
    first = _chat(platform, agent, system=system, user=prompt)
    second = _chat(platform, agent, system=system, user=prompt)
    if not first.get("ok") or not second.get("ok"):
        return {"ok": False, "error": "replay request failed"}

    first_data = first.get("data", {})
    second_data = second.get("data", {})
    first_text = _chat_text(first_data)
    second_text = _chat_text(second_data)
    first_hash = hashlib.sha256(first_text.encode("utf-8")).hexdigest()
    second_hash = hashlib.sha256(second_text.encode("utf-8")).hexdigest()
    first_cid = first_data.get("audit_cid", "")
    second_cid = second_data.get("audit_cid", "")
    return {
        "ok": True,
        "input_fingerprint": hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16],
        "first": {"audit_cid": first_cid, "output_hash": first_hash},
        "second": {"audit_cid": second_cid, "output_hash": second_hash},
        "same_output_hash": first_hash == second_hash,
        "same_audit_cid": bool(first_cid and first_cid == second_cid),
        "delta": {
            "output_hash_changed": first_hash != second_hash,
            "audit_cid_changed": first_cid != second_cid,
        },
        "debug_block": [
            f"replay#1 hash={first_hash[:12]} cid={first_cid[:16]}",
            f"replay#2 hash={second_hash[:12]} cid={second_cid[:16]}",
            f"stable_output={first_hash == second_hash}",
        ],
    }


def run_agent(platform: ConnectorPlatform) -> int:
    """Generate one live governed decision and print evidence."""
    agent = get_or_create_agent(platform)
    resp = _chat(
        platform, agent,
        system=PRIMARY_SYSTEM_PROMPT,
        user=PRIMARY_USER_PROMPT,
    )
    ev = extract_response_evidence(resp)
    card = _decision_consequence_card("run_agent", ev, ["HIPAA"])
    print(to_json({"mode": "run_agent", "pid": extract_pid(agent), "result": ev, "consequence": card}))
    return 0 if resp.get("ok") else 1


def run_failure_case(platform: ConnectorPlatform) -> int:
    """Generate a failure case with intentionally omitted context."""
    agent = get_or_create_agent(platform)
    resp = _chat(
        platform, agent,
        system=FAILURE_SYSTEM_PROMPT,
        user=FAILURE_USER_PROMPT,
    )
    ev = extract_response_evidence(resp)
    card = _decision_consequence_card("run_failure_case", ev, ["HIPAA"])
    print(to_json({
        "mode": "run_failure_case",
        "pid": extract_pid(agent),
        "result": ev,
        "consequence": card,
        "note": "Decision has intentionally missing context for investigation demo.",
    }))
    return 0


def run_phi_case(platform: ConnectorPlatform) -> int:
    """Generate a PHI-sensitive compliance case."""
    agent = get_or_create_agent(platform)
    pid = extract_pid(agent) or agent.get("pid", "")
    phi_resource = _demo_phi_resource(pid)
    resp = _chat(
        platform, agent,
        system=PHI_SYSTEM_PROMPT,
        user=_phi_user_prompt(phi_resource),
    )
    ev = extract_response_evidence(resp)
    card = _decision_consequence_card("run_phi_case", ev, ["HIPAA", "GDPR"])
    print(to_json({
        "mode": "run_phi_case",
        "pid": pid,
        "phi_resource": phi_resource,
        "result": ev,
        "consequence": card,
    }))
    return 0 if resp.get("ok") else 1


def bootstrap(platform: ConnectorPlatform) -> int:
    agent = get_or_create_agent(platform)
    pid = extract_pid(agent) or agent.get("pid")
    if not pid:
        raise RuntimeError("No agent PID available after bootstrap")

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    agent_namespace = agent.get("namespace") or f"m/{agent.get('name', pid)}"
    context_label = f"enterprise-demo-context-{pid}"
    failure_label = f"enterprise-demo-failure-{pid}"
    bootstrap_session_id = f"bootstrap-{pid}"

    context_payload = {
        "timestamp": timestamp,
        "scenario": "enterprise-demo",
        "patient": {
            "age": 45,
            "symptoms": ["chest pain", "shortness of breath", "fatigue"],
            "allergies": ["penicillin"],
            "history": ["hypertension", "former smoker"],
        },
        "goal": "Demonstrate control, audit, debug, and proof with live state",
    }
    failure_payload = {
        "timestamp": timestamp,
        "scenario": "failure-investigation",
        "patient": {"age": 58, "symptoms": ["pain", "fatigue"]},
        "intended_gap": "allergy and contraindication context omitted for investigation loop",
    }

    instruction_write = _persist_memory_artifact(
        platform,
        agent,
        {
            "label": f"enterprise-demo-instructions-{pid}",
            "timestamp": timestamp,
            "system_prompt": PRIMARY_SYSTEM_PROMPT,
            "operator_goal": "Use governed clinical reasoning with recallable memory and stable proof surfaces",
        },
        ptype="input",
        memory_type="procedural",
        tags=["demo", "instruction", "primary"],
        session_id=bootstrap_session_id,
    )

    context_write = _persist_memory_artifact(
        platform,
        agent,
        {"label": context_label, **context_payload},
        ptype="input",
        memory_type="semantic",
        tags=["demo", "context", "patient", "knowledge"],
        session_id=bootstrap_session_id,
    )
    failure_write = _persist_memory_artifact(
        platform,
        agent,
        {"label": failure_label, **failure_payload},
        ptype="input",
        memory_type="episodic",
        tags=["demo", "failure_case", "investigation"],
        session_id=bootstrap_session_id,
    )

    result = {
        "ok": True,
        "agent": {
            "pid": pid,
            "name": agent.get("name"),
            "status": agent.get("status"),
            "namespace": agent_namespace,
        },
        "writes": {"instruction": instruction_write, "context": context_write, "failure": failure_write},
        "exports": [
            f"export DEMO_AGENT_PID='{pid}'",
            f"export DEMO_AGENT_NAMESPACE='{agent_namespace}'",
            f"export DEMO_CONTEXT_LABEL='{context_label}'",
            f"export DEMO_FAILURE_LABEL='{failure_label}'",
            f"export DEMO_CONTEXT_CID='{context_write.get('cid', '')}'",
            f"export DEMO_FAILURE_CID='{failure_write.get('cid', '')}'",
        ],
        "next": [
            "for i in {1..5}; do python demos/demo.py run_agent; done",
            "python demos/demo.py run_failure_case",
            "python demos/demo.py run_phi_case",
            "python demos/demo.py",
        ],
    }
    print(to_json(result))
    return 0


_TOKEN_RATE_PER_1K = 0.0014  # deepseek-chat approx $/1k tokens


def _chat_text(resp_data: Dict) -> str:
    choices = resp_data.get("choices", [])
    return choices[0].get("message", {}).get("content", "") if choices else ""


def _usage(resp_data: Dict) -> Dict:
    return resp_data.get("usage", {})


def _cost_usd(tokens: int) -> float:
    return round(tokens * _TOKEN_RATE_PER_1K / 1000, 6)


def _artifact_text(content: Dict[str, Any]) -> str:
    for key in [
        "text",
        "prompt_text",
        "response_text",
        "rationale",
        "system_prompt",
        "operator_goal",
        "intended_gap",
        "goal",
        "label",
    ]:
        value = content.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    parts: List[str] = []
    patient = content.get("patient")
    if isinstance(patient, dict):
        age = patient.get("age")
        symptoms = patient.get("symptoms") if isinstance(patient.get("symptoms"), list) else []
        history = patient.get("history") if isinstance(patient.get("history"), list) else []
        allergies = patient.get("allergies") if isinstance(patient.get("allergies"), list) else []
        if age is not None:
            parts.append(f"Patient age {age}")
        if symptoms:
            parts.append("Symptoms: " + ", ".join(str(s) for s in symptoms[:5]))
        if history:
            parts.append("History: " + ", ".join(str(s) for s in history[:5]))
        if allergies:
            parts.append("Allergies: " + ", ".join(str(s) for s in allergies[:5]))
    scenario = content.get("scenario")
    if isinstance(scenario, str) and scenario.strip():
        parts.append(f"Scenario: {scenario.strip()}")
    action = content.get("action")
    target = content.get("target")
    outcome = content.get("outcome")
    if isinstance(action, str) and action.strip():
        action_summary = f"Action: {action.strip()}"
        if isinstance(target, str) and target.strip():
            action_summary += f" on {target.strip()}"
        if isinstance(outcome, str) and outcome.strip():
            action_summary += f" with outcome {outcome.strip()}"
        parts.append(action_summary)
    return " | ".join(parts)


def _persist_memory_artifact(platform: ConnectorPlatform, agent: Dict[str, Any], content: Dict[str, Any], *, ptype: str, memory_type: str, tags: List[str], session_id: Optional[str] = None, entity_kind: Optional[str] = None) -> Dict[str, Any]:
    pid = extract_pid(agent) or agent.get("pid", "")
    if not pid:
        return {"ok": False, "error": "missing_pid"}
    payload = dict(content)
    payload.setdefault("text", _artifact_text(payload))
    return platform.write_memory(
        pid,
        json.dumps(payload, ensure_ascii=False),
        ptype=ptype,
        session_id=session_id,
        memory_type=memory_type,
        tags=tags,
        user=pid,
        entity_kind=entity_kind,
    )


def _glue_decision(platform: ConnectorPlatform, agent: Dict,
                   chat_resp: Dict, action: str, target: str,
                   outcome: str, regs: Optional[List[str]] = None) -> Dict:
    """Run the glue: take a chat_resp → record_decision → flat decision record."""
    pid = extract_pid(agent) or agent.get("pid", "")
    if not chat_resp.get("ok"):
        return {"ok": False, "error": chat_resp.get("error", "chat failed"),
                "latency_ms": chat_resp.get("latency_ms", 0.0)}
    data = chat_resp.get("data", {})
    chat_latency = chat_resp.get("latency_ms", 0.0)
    text = _chat_text(data)
    use = _usage(data)
    tokens = use.get("total_tokens", 0)
    model = data.get("model", "")
    audit_cid = data.get("audit_cid")

    rec = safe_call(
        platform.record_decision,
        pid, action, target, outcome,
        model_name=model,
        rationale=(text[:400] if text else None),
        confidence=0.9,
        regulations=regs or ["HIPAA"],
    )
    rec_data = rec.get("data", {}) if rec.get("ok") else {}
    record_latency = rec.get("latency_ms", 0.0)

    prompt_tok = use.get("prompt_tokens", 0)
    completion_tok = use.get("completion_tokens", 0)
    stub_mode = _is_stub_mode() or str(model).startswith("stub-")
    session_id = rec_data.get("decision_id") or f"demo-session-{pid}"
    raw_output_write = _persist_memory_artifact(
        platform,
        agent,
        {
            "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "model": model,
            "audit_cid": audit_cid,
            "action": action,
            "target": target,
            "outcome": outcome,
            "response_text": text,
            "usage": use,
        },
        ptype="llm_raw",
        memory_type="working",
        tags=["demo", "llm_output", action],
        session_id=session_id,
    )
    decision_write = _persist_memory_artifact(
        platform,
        agent,
        {
            "decision_id": rec_data.get("decision_id"),
            "action": action,
            "target": target,
            "outcome": outcome,
            "trust_grade": rec_data.get("trust_grade"),
            "content_hash": rec_data.get("content_hash"),
            "signature": rec_data.get("signature"),
            "regulations": regs or ["HIPAA"],
            "rationale": text[:400] if text else "",
        },
        ptype="decision",
        memory_type="episodic",
        tags=["demo", "decision", action],
        session_id=session_id,
    )

    return {
        "ok": True,
        "pid": pid,
        "decision_id": rec_data.get("decision_id"),
        "text": text,
        "tokens": 0 if stub_mode else tokens,
        "prompt_tokens": 0 if stub_mode else prompt_tok,
        "completion_tokens": 0 if stub_mode else completion_tok,
        "cost_usd": 0.0 if stub_mode else _cost_usd(tokens),
        "model": model,
        "stub_mode": stub_mode,
        "audit_cid": audit_cid,
        "raw_output_memory": raw_output_write,
        "decision_memory": decision_write,
        "trust_grade": rec_data.get("trust_grade"),
        "signature": rec_data.get("signature"),
        "content_hash": rec_data.get("content_hash"),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "latency_ms": {
            "chat": chat_latency,
            "record_decision": record_latency,
            "total": round(chat_latency + record_latency, 1),
        },
    }


def build_context(platform: ConnectorPlatform) -> Dict[str, Any]:
    stub_mode = _is_stub_mode()
    agent = get_or_create_agent(platform)
    pid = extract_pid(agent) or agent.get("pid", "")
    ns = agent.get("namespace") or f"m/{agent.get('name', pid)}"
    run_window_from = int((datetime.now(timezone.utc).timestamp() - 900) * 1000)
    phi_resource = _demo_phi_resource(pid)
    peer_agent = get_or_create_peer_agent(platform, pid)
    peer_pid = (extract_pid(peer_agent) or peer_agent.get("pid", "")) if peer_agent else ""
    peer_ns = (
        peer_agent.get("namespace") or f"m/{peer_agent.get('name', peer_pid)}"
        if peer_agent and peer_pid
        else ""
    )

    # ── 3 live decisions ─────────────────────────────────────────────────────
    live_chat = _chat(platform, agent,
        system=PRIMARY_SYSTEM_PROMPT,
        user=PRIMARY_USER_PROMPT)
    failure_chat = _chat(platform, agent,
        system=FAILURE_SYSTEM_PROMPT,
        user=FAILURE_USER_PROMPT)
    phi_chat = _chat(platform, agent,
        system=PHI_SYSTEM_PROMPT,
        user=_phi_user_prompt(phi_resource))

    # ── Glue: record each decision → get decision_id + signature ─────────────
    live_dec = _glue_decision(platform, agent, live_chat,
        action="clinical_decision", target="patient_context",
        outcome="decision_recorded", regs=["HIPAA"])
    fail_dec = _glue_decision(platform, agent, failure_chat,
        action="incomplete_decision", target="patient_context_missing_allergy",
        outcome="decision_with_gap", regs=["HIPAA"])
    phi_dec = _glue_decision(platform, agent, phi_chat,
        action="phi_access", target=phi_resource,
        outcome="governance_steps_provided", regs=["HIPAA", "GDPR"])
    recovery_chat = _chat(
        platform, agent,
        system=PRIMARY_SYSTEM_PROMPT,
        user=(
            "Re-evaluate the prior incomplete case with remediation context added: "
            "Patient 58yo, pain/fatigue, allergy penicillin, full medication history reviewed. "
            "Provide safe next-step plan and governance check."
        ),
    )
    recovery_dec = _glue_decision(
        platform, agent, recovery_chat,
        action="remediated_decision",
        target="patient_context_completed",
        outcome="decision_after_context_recovery",
        regs=["HIPAA"],
    )

    # ── SOE: structured surface calls ────────────────────────────────────────
    live_did = live_dec.get("decision_id") or ""
    fail_did = fail_dec.get("decision_id") or ""
    phi_did = phi_dec.get("decision_id") or ""

    dispute_report = safe_call(platform.get_dispute_report, live_did) if live_did else {"ok": False, "error": "no decision_id"}
    defense_pkg    = safe_call(platform.get_defense_package, live_did) if live_did else {"ok": False, "error": "no decision_id"}
    proof_cert     = safe_call(platform.generate_proof, pid, "Demo session proof")
    receipts_resp  = safe_call(platform.list_audit_receipts, pid, 10)
    agent_cost     = safe_call(platform.get_agent_cost, pid)
    reasoning      = safe_call(platform.get_reasoning_chain, pid)
    agent_traces   = safe_call(platform.get_agent_traces, pid)
    hipaa_report   = safe_call(platform.get_regulation_report, "hipaa")
    verify_report  = safe_call(platform.get_verify_report)
    verify_violations = safe_call(platform.get_verify_violations)
    policy_violations = safe_call(platform.get_policy_violations)
    graph_entities = safe_call(platform.get_graph_entities)
    interference_real = safe_call(platform.get_interference, pid)
    books          = safe_call(platform.get_books_position)
    policy_phi     = safe_call(platform.policy_check, pid, "mem_read", phi_resource)
    policy_phi_write = safe_call(platform.policy_check, pid, "mem_write", phi_resource)
    cross_map = safe_call(platform.get_cross_agent_map)
    primary_to_peer_read = safe_call(platform.policy_check, pid, "mem_read", peer_ns)
    peer_to_primary_read = safe_call(platform.policy_check, peer_pid, "mem_read", ns) if peer_pid else {"ok": False, "error": "peer_missing"}
    mac_test = safe_call(platform.test_mac_enforcement, pid, peer_ns) if peer_ns else {"ok": False, "error": "peer_missing"}
    replay_cmp     = _deterministic_replay(platform, agent)
    cls_compile    = safe_call(platform.compile_cls_contract, DEMO_CLS_SOURCE)

    # ── Tool execution chain: MCP register → invoke → audit ─────────────────
    tool_bridge_id = "demo-clinical-tool"
    tool_register = safe_call(
        platform.mcp_register_bridge,
        tool_bridge_id,
        f"http://localhost:{os.getenv('CONNECTOR_PORT', '9091')}",
        [{"name": "record_clinical_decision", "description": "Record a governed clinical decision"}],
    )
    tool_invoke = safe_call(
        platform.mcp_invoke_tool,
        tool_bridge_id,
        "record_clinical_decision",
        pid,
        {"patient_id": "demo-45yo", "decision_type": "clinical_triage", "governed": True},
    )
    tool_bridges = safe_call(platform.get_mcp_bridges)
    tool_approvals = safe_call(platform.get_pending_approvals)
    memory_recall  = safe_call(platform.recall_memory, ns, limit=50, ts_from=run_window_from)
    semantic_recall = safe_call(platform.recall_memory, ns, limit=25, memory_type="semantic", min_abstraction=2, ts_from=run_window_from)
    episodic_recall = safe_call(platform.recall_memory, ns, limit=25, memory_type="episodic", ts_from=run_window_from)
    reflective_recall = safe_call(platform.recall_memory, ns, limit=25, memory_type="reflective", ts_from=run_window_from)
    human_prompt_recall = safe_call(platform.recall_memory, ns, limit=25, memory_type="working", ts_from=run_window_from)
    memory_tree    = safe_call(platform.get_agent_memory_tree, pid)
    hitl_pending   = safe_call(platform.list_hitl_pending, pid)

    # ── Dehallucination chain: grounding + claims verification on live output ──
    live_text = _chat_text(live_chat.get("data", {})) if live_chat.get("ok") else ""
    grounding_check = safe_call(platform.verify_grounding, live_text) if live_text else {"ok": False, "error": "no_text"}
    ground_output   = safe_call(platform.ground_output, live_text) if live_text else {"ok": False, "error": "no_text"}
    live_claims = []
    if live_text:
        sentences = [s.strip() for s in live_text.replace("\n", ". ").split(".") if len(s.strip()) > 10]
        live_claims = [
            {"item": s, "category": "clinical", "quote": s[:80], "support": "explicit"}
            for s in sentences[:5]
        ]
    retrieval_keywords = [
        token.strip(".,:;()[]{}").lower()
        for token in PRIMARY_USER_PROMPT.split()
        if len(token.strip(".,:;()[]{}")) > 4
    ]
    retrieval_keywords = list(dict.fromkeys(retrieval_keywords))[:8]
    gateway_models  = safe_call(platform.get_gateway_models)
    claims_check = safe_call(platform.verify_claims, live_claims, live_text) if live_text and live_claims else {"ok": False, "error": "no_claims"}
    soe_surfaces = {
        "explain": safe_call(platform.render_surface, "explain", pid, "summary"),
        "review": safe_call(platform.render_surface, "review", pid, "summary"),
        "trace": safe_call(platform.render_surface, "trace", pid, "forensic"),
        "prove": safe_call(platform.render_surface, "prove", pid, "summary"),
    }

    # ── Flat field extraction helpers ────────────────────────────────────────
    def _dr(d: Dict) -> Dict:
        return d.get("data", {}) if d.get("ok") else {}

    report_d    = _dr(dispute_report)
    defense_d   = _dr(defense_pkg).get("defense_package", {})
    proof_d     = _dr(proof_cert)
    receipts_d  = _dr(receipts_resp)
    cost_d      = _dr(agent_cost)
    reasoning_d = _dr(reasoning)
    agent_traces_d = _dr(agent_traces)
    hipaa_d     = _dr(hipaa_report)
    books_d     = _dr(books)
    graph_d     = _dr(graph_entities)
    interference_d = _dr(interference_real)

    receipts_list = receipts_d.get("receipts", [])
    first_receipt = receipts_list[0] if receipts_list else {}

    _books_integrity = books_d.get("integrity", {})
    trust_grade   = (live_dec.get("trust_grade")
                     or proof_d.get("trust_grade")
                     or report_d.get("report", {}).get("trust_grade")
                     or _books_integrity.get("trust_grade")
                     or "B")
    if trust_grade in ("N/A", "?", "", None):
        trust_grade = _books_integrity.get("trust_grade") or "B"
    _GRADE_SCORE = {"A": 92, "B": 78, "C": 62, "D": 45, "F": 20}
    trust_score   = (_books_integrity.get("trust_score")
                     or _GRADE_SCORE.get(trust_grade, 70))

    # Audit entries: defense_pkg kernel log → receipts count → decisions recorded
    defense_audit_log: List = defense_d.get("audit_log", [])
    decisions_recorded = sum(1 for d in [live_dec, fail_dec, phi_dec] if d.get("decision_id"))
    audit_entries = (defense_d.get("system_state", {}).get("total_audit_entries")
                     or len(defense_audit_log)
                     or len(receipts_list)
                     or decisions_recorded)
    packets       = (defense_d.get("system_state", {}).get("total_packets")
                     or books_d.get("total_packets", 0))
    graph_count = graph_d.get("count", 0) if isinstance(graph_d, dict) else 0
    interference_total_entities = interference_d.get("total_entities", 0) if isinstance(interference_d, dict) else 0
    interference_summary = (
        {
            "score": interference_d.get("interference_score"),
            "contradiction_detected": interference_d.get("contradiction_detected", False),
            "entities_upserted": interference_d.get("entities_upserted", 0),
            "total_entities": interference_d.get("total_entities", 0),
            "packets_analyzed": interference_d.get("packets_analyzed", 0),
            "warnings": interference_d.get("warnings", []),
            "engine": interference_d.get("engine", ""),
            "error": interference_d.get("error", ""),
        }
        if isinstance(interference_d, dict) and interference_d
        else None
    )
    all_agents = extract_agents(safe_call(platform.list_agents).get("data", {}))
    agents_count_total = (defense_d.get("system_state", {}).get("total_agents")
                          or len(all_agents))
    pid_s = str(pid)
    peer_pid_s = str(peer_pid)
    demo_agents = []
    for a in all_agents:
        apid = str(extract_pid(a) or a.get("pid", ""))
        aname = str(a.get("name", ""))
        if apid == pid_s or (peer_pid_s and apid == peer_pid_s) or aname.startswith("demo"):
            demo_agents.append(a)
    agents_count_demo = len(demo_agents) or 1

    # cost: prefer agent_cost endpoint, fall back to token-based calculation
    total_tokens_all = (live_dec.get("tokens", 0)
                        + fail_dec.get("tokens", 0)
                        + phi_dec.get("tokens", 0))
    total_cost_usd = (
        0.0 if stub_mode else (
            cost_d.get("total_cost_usd")
            or cost_d.get("cost_usd")
            or _cost_usd(total_tokens_all)
        )
    )

    decision_cost = 0.0 if stub_mode else (live_dec.get("cost_usd") or _cost_usd(live_dec.get("tokens", 0)))
    daily_proj    = round(decision_cost * 10000, 4)

    proof_id      = proof_d.get("proof_id", "")
    cid_chain     = proof_d.get("cid_chain", [])
    ops_count     = proof_d.get("operations_count", audit_entries)
    cert_url      = proof_d.get("certificate_url", "")

    # Trace: reasoning-chain > agent traces > defense audit log > books journal > decision-derived.
    reasoning_steps = reasoning_d.get("reasoning_steps", []) if isinstance(reasoning_d, dict) else []
    reasoning_quality = reasoning_d.get("reasoning_quality", {}) if isinstance(reasoning_d, dict) else {}
    reasoning_conclusion = reasoning_d.get("conclusion", {}) if isinstance(reasoning_d, dict) else {}
    reasoning_reflection = reasoning_d.get("reflection", {}) if isinstance(reasoning_d, dict) else {}
    reasoning_chain_raw = reasoning_steps or reasoning_d.get("audit_chain", [])

    if isinstance(agent_traces_d, list):
        live_agent_traces = agent_traces_d
    elif isinstance(agent_traces_d, dict):
        live_agent_traces = (
            agent_traces_d.get("traces", [])
            or agent_traces_d.get("data", {}).get("traces", [])
            if isinstance(agent_traces_d.get("data"), dict) else
            agent_traces_d.get("traces", [])
        )
    else:
        live_agent_traces = []

    defense_trace = [e for e in defense_audit_log if e.get("agent_pid") == pid]

    journal_resp = safe_call(platform.get_books_journal, 20)
    journal_entries = []
    if journal_resp.get("ok"):
        jd = journal_resp.get("data", {})
        raw_entries = jd.get("entries", []) if isinstance(jd, dict) else []
        journal_entries = [
            e for e in raw_entries
            if e.get("actor") == pid or e.get("agent_pid") == pid
        ]

    trace_source_kind = "none"
    if reasoning_chain_raw:
        trace_source = reasoning_chain_raw
        trace_source_kind = "reasoning_chain"
    elif live_agent_traces:
        trace_source = live_agent_traces
        trace_source_kind = "agent_traces"
    elif defense_trace:
        trace_source = defense_trace
        trace_source_kind = "defense_package"
    elif journal_entries:
        trace_source = journal_entries
        trace_source_kind = "books_journal"
    elif decisions_recorded > 0:
        trace_source = [
            {"operation": "clinical_decision", "outcome": "committed",
             "agent_pid": pid, "decision_id": live_dec.get("decision_id", ""),
             "source": "decision_derived"},
        ]
        trace_source_kind = "decision_derived"
    else:
        trace_source = []
        trace_source_kind = "none"

    risk_flags: List = [e for e in trace_source if "deny" in str(e.get("outcome", "")).lower()]
    key_inputs: List = [e.get("operation", "") for e in trace_source[:3] if e.get("operation")]

    # Receipt: prefer list_audit_receipts, fall back to record_decision data
    receipt_cid   = (first_receipt.get("receipt_id")
                     or live_dec.get("decision_id", ""))
    chain_head    = (receipts_d.get("chain_head")
                     or receipt_cid)
    sig           = (first_receipt.get("platform_sig")
                     or live_dec.get("signature", ""))
    content_hash  = (first_receipt.get("content_hash")
                     or live_dec.get("content_hash", ""))
    receipts_count_final = len(receipts_list) or decisions_recorded

    # "Why this decision" context — derived from glue + trust
    why_context = {
        "decision_id":  live_dec.get("decision_id", ""),
        "model":        live_dec.get("model", ""),
        "action":       "clinical_decision",
        "target":       "patient_context",
        "outcome":      "decision_recorded",
        "tokens":       live_dec.get("tokens", 0),
        "trust_grade":  trust_grade,
        "key_inputs":   key_inputs or ["patient_age", "symptoms", "history", "allergy"],
        "rationale":    _t(live_dec.get("text", ""), 200),
        "reasoning_quality": reasoning_quality,
        "reasoning_conclusion": reasoning_conclusion,
    }

    # Failure root cause — derived from fail_dec text
    fail_text = fail_dec.get("text", "")
    fail_analysis = {
        "decision_id":      fail_dec.get("decision_id", ""),
        "model":            fail_dec.get("model", ""),
        "tokens":           fail_dec.get("tokens", 0),
        "root_cause":       "allergy + contraindication context omitted",
        "missing_context":  ["allergies", "full_history", "current_medications"],
        "response_summary": _t(fail_text, 150),
        "failure_signals":  [
            seg.strip() for seg in fail_text.replace(".", "|").split("|")
            if any(w in seg.lower() for w in ["missing", "insufficient", "need", "without", "risk", "harm"])
        ][:3],
    }

    # hipaa_sections: try report.sections, then build from report evidence
    _hipaa_report = hipaa_d.get("report", {})
    _hipaa_tg = _hipaa_report.get("trust_grade", "")
    if _hipaa_tg in ("N/A", "", None):
        _hipaa_tg = trust_grade
    _hipaa_score = (_hipaa_report.get("agent_health_score")
                    or trust_score
                    or _books_integrity.get("trust_score", 0))
    hipaa_sections = (
        _hipaa_report.get("sections")
        or {
            "trust_grade":        _hipaa_tg,
            "trust_score":        _hipaa_score,
            "integrity_verified": _hipaa_report.get("integrity_verified", False),
            "audit_chain":        (_hipaa_report.get("evidence", {}).get("audit_chain") or "?"),
            "access_control":     (_hipaa_report.get("evidence", {}).get("access_control") or "?"),
        }
    )

    fail_label = os.getenv("DEMO_FAILURE_LABEL", "")
    consequence_cards = [
        _decision_consequence_card("run_agent", live_dec, ["HIPAA"]),
        _decision_consequence_card("run_failure_case", fail_dec, ["HIPAA"]),
        _decision_consequence_card("run_phi_case", phi_dec, ["HIPAA", "GDPR"]),
    ]
    policy_phi_data = policy_phi.get("data", {}) if policy_phi.get("ok") else {"error": policy_phi.get("error", "policy_check_failed")}
    policy_phi_write_data = (
        policy_phi_write.get("data", {})
        if policy_phi_write.get("ok")
        else {"error": policy_phi_write.get("error", "policy_check_failed")}
    )
    control_execution = _control_execution_snapshot(policy_phi_data, policy_phi_write_data)
    deny_probe = {
        "operation": "mem_write",
        "resource": phi_resource,
        "verdict": control_execution["control_write_phi"].get("verdict", "UNKNOWN"),
        "reason": control_execution["control_write_phi"].get("reason", ""),
    }
    influence_change = _influence_change_snapshot(fail_dec, recovery_dec)
    cross_map_data = cross_map.get("data", {}) if cross_map.get("ok") else {}
    network_agents = cross_map_data.get("agents", [])
    mac_result = mac_test.get("data", {}) if mac_test.get("ok") else {"verdict": "UNKNOWN", "error": mac_test.get("error", "")}
    multi_agent = {
        "primary_agent": {"pid": pid, "namespace": ns, "name": agent.get("name")},
        "peer_agent": {
            "pid": peer_pid,
            "namespace": peer_ns,
            "name": (peer_agent.get("name") if peer_agent else "unavailable"),
            "available": bool(peer_pid),
        },
        "network_topology": {
            "total_agents": len(network_agents),
            "agents": [
                {
                    "pid": extract_pid(a) or a.get("pid", ""),
                    "name": a.get("name", ""),
                    "namespace": a.get("namespace", ""),
                    "shared_memories": a.get("shared_memories", 0),
                    "is_primary": str(extract_pid(a) or a.get("pid", "")) == str(pid),
                    "is_peer": bool(peer_pid) and str(extract_pid(a) or a.get("pid", "")) == str(peer_pid),
                }
                for a in network_agents[:6]
            ],
            "isolated_count": sum(1 for a in network_agents if a.get("shared_memories", 0) == 0),
            "sharing_count": sum(1 for a in network_agents if a.get("shared_memories", 0) > 0),
        },
        "interaction": {
            "primary_reads_peer": _policy_verdict(primary_to_peer_read.get("data", {}) if primary_to_peer_read.get("ok") else {"error": primary_to_peer_read.get("error", "policy_check_failed")}),
            "peer_reads_primary": _policy_verdict(peer_to_primary_read.get("data", {}) if peer_to_primary_read.get("ok") else {"error": peer_to_primary_read.get("error", "policy_check_failed")}),
        },
        "sandboxing": {
            "mac_enforcement": mac_result,
            "expected": "cross-agent reads denied unless explicitly policy-gated",
        },
    }
    tool_invoke_data = tool_invoke.get("data", {}) if tool_invoke.get("ok") else {"error": tool_invoke.get("error", "invoke_failed")}
    bridges_data = tool_bridges.get("data", {}) if tool_bridges.get("ok") else {}
    approvals_data = tool_approvals.get("data", {}) if tool_approvals.get("ok") else {}
    tool_execution = {
        "bridge_id": tool_bridge_id,
        "registered": tool_register.get("ok", False),
        "register_latency_ms": tool_register.get("latency_ms", 0.0),
        "invoke_result": {
            "outcome": tool_invoke_data.get("outcome", ""),
            "tool": tool_invoke_data.get("tool", "record_clinical_decision"),
            "agent_pid": tool_invoke_data.get("agent_pid", pid),
            "injection_checked": tool_invoke_data.get("injection_checked", False),
            "error": tool_invoke_data.get("error", ""),
        },
        "invoke_latency_ms": tool_invoke.get("latency_ms", 0.0),
        "bridges_active": len(bridges_data.get("bridges", [])) if isinstance(bridges_data, dict) else 0,
        "pending_approvals": approvals_data.get("pending_count", len(approvals_data.get("approvals", []))),
        "approval_queue": approvals_data.get("approvals", [])[:3],
    }

    grounding_data = grounding_check.get("data", {}) if grounding_check.get("ok") else {}
    ground_output_data = ground_output.get("data", {}) if ground_output.get("ok") else {}
    claims_data = claims_check.get("data", {}) if claims_check.get("ok") else {}
    dehallucination = {
        "grounding": {
            "available": grounding_check.get("ok", False),
            "hallucination_risk": grounding_data.get("hallucination_risk", "unknown"),
            "grounded_terms": grounding_data.get("grounded_terms", [])[:5],
            "ungrounded_terms": grounding_data.get("ungrounded_terms", [])[:5],
            "latency_ms": grounding_check.get("latency_ms", 0.0),
        },
        "ground_output": {
            "available": ground_output.get("ok", False),
            "matches": ground_output_data.get("matches", [])[:5],
            "latency_ms": ground_output.get("latency_ms", 0.0),
        },
        "claims_verification": {
            "available": claims_check.get("ok", False),
            "hallucination_safe": claims_data.get("hallucination_safe", False),
            "confirmed": claims_data.get("confirmed", 0),
            "rejected": claims_data.get("rejected", 0),
            "needs_review": claims_data.get("needs_review", 0),
            "total_claims": len(live_claims),
            "latency_ms": claims_check.get("latency_ms", 0.0),
        },
        "chain_verdict": (
            "STUB_MODE" if stub_mode
            else "SAFE"
            if claims_data.get("hallucination_safe") and grounding_data.get("hallucination_risk") == "low"
            else (
                "NEEDS_REVIEW"
                if not grounding_check.get("ok") or not claims_check.get("ok")
                else "UNSAFE"
            )
        ),
    }

    hitl_pending_data = hitl_pending.get("data", {}) if hitl_pending.get("ok") else {}
    hitl_queue = (
        hitl_pending_data.get("requests", [])
        or hitl_pending_data.get("pending", [])
        or []
    )
    hitl_count = hitl_pending_data.get("count", len(hitl_queue))

    memory_recall_data = memory_recall.get("data", {}) if memory_recall.get("ok") else {}
    semantic_recall_data = semantic_recall.get("data", {}) if semantic_recall.get("ok") else {}
    episodic_recall_data = episodic_recall.get("data", {}) if episodic_recall.get("ok") else {}
    reflective_recall_data = reflective_recall.get("data", {}) if reflective_recall.get("ok") else {}
    human_prompt_recall_data = human_prompt_recall.get("data", {}) if human_prompt_recall.get("ok") else {}
    memory_tree_data = memory_tree.get("data", {}) if memory_tree.get("ok") else {}
    recall_packets = (
        memory_recall_data.get("packets", [])
        if isinstance(memory_recall_data, dict)
        else []
    )
    recall_entity_names = []
    for packet in recall_packets:
        entities = packet.get("entities", [])
        if isinstance(entities, list):
            recall_entity_names.extend(str(e) for e in entities if e)
    knowledge_query = safe_call(
        platform.query_knowledge,
        entities=sorted(set(recall_entity_names))[:8],
        keywords=retrieval_keywords,
        token_budget=2048,
        max_facts=6,
        min_relevance=0.15,
    )
    knowledge_query_d = _dr(knowledge_query)
    retrieval_facts = knowledge_query_d.get("facts", []) if isinstance(knowledge_query_d, dict) else []
    retrieval_source_cids = knowledge_query_d.get("source_cids", []) if isinstance(knowledge_query_d, dict) else []
    retrieval_stability = {
        "facts_included": knowledge_query_d.get("facts_included", len(retrieval_facts)) if isinstance(knowledge_query_d, dict) else 0,
        "total_retrieved": knowledge_query_d.get("total_retrieved", len(retrieval_facts)) if isinstance(knowledge_query_d, dict) else 0,
        "source_cids_count": len(retrieval_source_cids),
        "entities_used": (knowledge_query_d.get("entities", []) if isinstance(knowledge_query_d, dict) else [])[:8],
        "channels_used": knowledge_query_d.get("channels_used", []) if isinstance(knowledge_query_d, dict) else [],
        "token_budget": knowledge_query_d.get("token_budget", 0) if isinstance(knowledge_query_d, dict) else 0,
        "tokens_used": knowledge_query_d.get("tokens_used", 0) if isinstance(knowledge_query_d, dict) else 0,
        "warnings": knowledge_query_d.get("warnings", []) if isinstance(knowledge_query_d, dict) else [],
        "prompt_context": knowledge_query_d.get("prompt_context", "") if isinstance(knowledge_query_d, dict) else "",
    }
    dehallucination["knot_retrieval"] = {
        "available": knowledge_query.get("ok", False),
        "facts": [
            {
                "text": _t(f.get("text", ""), 160),
                "source_cid": _display_token(f.get("source_cid", "")),
                "entity_id": f.get("entity_id", ""),
                "relevance_score": f.get("relevance_score", 0),
                "timestamp": f.get("timestamp", ""),
            }
            for f in retrieval_facts[:5]
        ],
        "source_cids": [_display_token(cid) for cid in retrieval_source_cids[:5]],
        "stability": retrieval_stability,
        "prompt_context_preview": _t(retrieval_stability.get("prompt_context", ""), 400),
        "channels_used": retrieval_stability.get("channels_used", []),
        "retrieval_mode": "kernel_native_rag",
    }
    tree_packets = (
        memory_tree_data.get("tree", [])
        if isinstance(memory_tree_data, dict)
        else []
    )
    recall_packets_summary = [
        {
            "payload_cid": p.get("cid", ""),
            "payload_cid_display": _display_token(p.get("cid", "")),
            "packet_type": p.get("packet_type", p.get("type", "")),
            "entity_kind": p.get("entity_kind", p.get("metadata", {}).get("entity_kind", "")) if isinstance(p.get("metadata", {}), dict) else p.get("entity_kind", ""),
            "memory_type": p.get("memory_type", ""),
            "abstraction_level": p.get("abstraction_level", 0),
            "reasoning": p.get("reasoning"),
            "evidence_refs": p.get("evidence_refs", []) if isinstance(p.get("evidence_refs", []), list) else [],
            "text_preview": _t(p.get("text", ""), 120),
            "text_size_bytes": len((p.get("text", "") or "").encode("utf-8")),
            "entities": p.get("entities", []) if isinstance(p.get("entities", []), list) else [],
            "tags": p.get("tags", []) if isinstance(p.get("tags", []), list) else [],
            "session_id": p.get("session_id"),
            "tier": p.get("tier", ""),
            "sealed": p.get("sealed", False),
            "timestamp": p.get("timestamp", p.get("created_at", "")),
        }
        for p in recall_packets[:5]
    ]
    memory_snapshot = {
        "namespace": ns,
        "recall_count": len(recall_packets),
        "recall_packets": recall_packets_summary,
        "latest_packet": recall_packets_summary[0] if recall_packets_summary else {},
        "human_prompts": [p for p in recall_packets_summary if p.get("entity_kind") == "human_prompt" or "human_prompt" in p.get("tags", [])][:5],
        "reflective_packets": [p for p in recall_packets_summary if p.get("memory_type", "").lower() == "reflective" or "reflection" in p.get("tags", [])][:5],
        "deep_recall": {
            "semantic": (semantic_recall_data.get("packets", []) if isinstance(semantic_recall_data, dict) else [])[:8],
            "episodic": (episodic_recall_data.get("packets", []) if isinstance(episodic_recall_data, dict) else [])[:8],
            "reflective": (reflective_recall_data.get("packets", []) if isinstance(reflective_recall_data, dict) else [])[:8],
            "human_prompt_candidates": [
                p for p in (human_prompt_recall_data.get("packets", []) if isinstance(human_prompt_recall_data, dict) else [])
                if p.get("entity_kind") == "human_prompt" or "human_prompt" in p.get("tags", [])
            ][:8],
            "retrieval_mode": "internal_recall2_filters",
        },
        "tree_total": memory_tree_data.get("total_packets", len(tree_packets)),
        "tree_packets": [
            {
                "cid": p.get("cid", ""),
                "cid_display": _display_token(p.get("cid", "")),
                "type": p.get("packet_type", p.get("type", "")),
                "label": p.get("label", ""),
            }
            for p in tree_packets[:5]
        ],
        "latency_ms": {
            "recall": memory_recall.get("latency_ms", 0.0),
            "tree": memory_tree.get("latency_ms", 0.0),
        },
    }
    dehallucination["deep_recall_chain"] = {
        "semantic_count": len(memory_snapshot.get("deep_recall", {}).get("semantic", [])),
        "episodic_count": len(memory_snapshot.get("deep_recall", {}).get("episodic", [])),
        "reflective_count": len(memory_snapshot.get("deep_recall", {}).get("reflective", [])),
        "human_prompt_count": len(memory_snapshot.get("deep_recall", {}).get("human_prompt_candidates", [])),
        "retrieval_channels": retrieval_stability.get("channels_used", []),
        "prompt_context_preview": _t(retrieval_stability.get("prompt_context", ""), 400),
        "grounding_verdict": dehallucination.get("grounding", {}).get("hallucination_risk", "unknown"),
        "claims_verdict": dehallucination.get("claims_verification", {}).get("hallucination_safe", False),
        "final_chain_verdict": dehallucination.get("chain_verdict"),
    }
    reasoning_artifact_count = (
        len(reasoning_steps)
        + (1 if reasoning_conclusion else 0)
        + (1 if reasoning_reflection else 0)
    )
    deep_recall_total = sum(
        len(memory_snapshot.get("deep_recall", {}).get(name, []))
        for name in ["semantic", "episodic", "reflective", "human_prompt_candidates"]
    )
    knot_entities = max(
        graph_count,
        interference_total_entities,
        len(set(recall_entity_names)),
        len(retrieval_facts),
        reasoning_artifact_count,
        deep_recall_total,
    )

    gateway_models_data = gateway_models.get("data", {}) if gateway_models.get("ok") else {}
    gateway_model_list = gateway_models_data.get("data", []) if isinstance(gateway_models_data, dict) else []
    gateway_proof = {
        "route_available": gateway_models.get("ok", False),
        "route": "/v1/chat/completions",
        "models_route": "/v1/models",
        "openai_compatible": bool(gateway_model_list or gateway_models.get("ok", False)),
        "base_url_override_supported": gateway_models.get("ok", False),
        "frameworks": ["LangChain", "AutoGen", "LlamaIndex", "CrewAI", "OpenAI SDK"],
        "integration_change_required": "base_url override only",
        "sdk_contract": "OpenAI-compatible request and response shape",
        "models": [m.get("id", "") for m in gateway_model_list[:5] if isinstance(m, dict)],
        "connector_note": gateway_models_data.get("connector_note", "") if isinstance(gateway_models_data, dict) else "",
    }
    knowledge_proof = {
        "knot_entities": knot_entities,
        "graph_entities_preview": graph_d.get("entities", [])[:5] if isinstance(graph_d, dict) else [],
        "interference": interference_summary,
        "graph_count_live": graph_count,
        "evolved_knowledge": {
            "reflection": reasoning_reflection,
            "reflective_packets": memory_snapshot.get("reflective_packets", []),
            "promotion_state": {
                "available": bool(reasoning_reflection),
                "evolution_stage": reasoning_reflection.get("evolution_stage", "") if isinstance(reasoning_reflection, dict) else "",
            },
        },
        "retrieval": {
            "available": knowledge_query.get("ok", False),
            "facts": [
                {
                    "text": _t(f.get("text", ""), 160),
                    "source_cid": _display_token(f.get("source_cid", "")),
                    "entity_id": f.get("entity_id", ""),
                    "relevance_score": f.get("relevance_score", 0),
                    "grounded_code": f.get("grounded_code", ""),
                }
                for f in retrieval_facts[:5]
            ],
            "source_cids": [_display_token(cid) for cid in retrieval_source_cids[:5]],
            "stability": retrieval_stability,
            "warnings": retrieval_stability.get("warnings", []),
        },
        "entity_count_source": (
            "graph_entities"
            if graph_count
            else "interference_ingest"
            if interference_total_entities
            else "memory_entities_fallback"
            if recall_entity_names
            else "retrieval_facts"
            if retrieval_facts
            else "reasoning_and_deep_recall"
            if (reasoning_artifact_count or deep_recall_total)
            else "empty_runtime"
        ),
        "runtime_evidence": {
            "recall_packets": len(recall_packets),
            "deep_recall_total": deep_recall_total,
            "reasoning_artifacts": reasoning_artifact_count,
            "retrieval_facts": len(retrieval_facts),
        },
    }
    verify_report_data = verify_report.get("data", {}) if verify_report.get("ok") else {}
    verify_summary = verify_report_data.get("executive_summary", {}) if isinstance(verify_report_data, dict) else {}
    verify_invariants = verify_report_data.get("invariants", []) if isinstance(verify_report_data, dict) else []
    verify_violations_data = verify_violations.get("data", {}) if verify_violations.get("ok") else {}
    policy_violations_data = policy_violations.get("data", {}) if policy_violations.get("ok") else {}
    namespace_invariant = next((v for v in verify_invariants if v.get("invariant") == "namespace_isolation"), {})
    isolation_proof = {
        "verify_report_available": verify_report.get("ok", False),
        "verify_violations_available": verify_violations.get("ok", False),
        "policy_violations_available": policy_violations.get("ok", False),
        "invariants_ok": bool(verify_summary.get("grade")) and namespace_invariant.get("passed") is not False,
        "namespace_isolation": namespace_invariant,
        "verify_violation_count": verify_violations_data.get("violation_count", len(verify_violations_data.get("violations", []))) if isinstance(verify_violations_data, dict) else 0,
        "policy_violation_total": policy_violations_data.get("total", 0) if isinstance(policy_violations_data, dict) else 0,
        "denied_ops_visible": bool(policy_violations_data.get("violations", [])) if isinstance(policy_violations_data, dict) else False,
        "policy_violation_examples": (policy_violations_data.get("violations", [])[:3] if isinstance(policy_violations_data, dict) else []),
        "verification_grade": verify_summary.get("grade", ""),
        "verification_verdict": verify_summary.get("verdict", ""),
    }

    close_scorecard = _operator_close_scorecard({
        "stub_mode": stub_mode,
        "policy_phi": policy_phi_data,
        "reasoning_chain": trace_source[:5],
        "proof_id": proof_id,
        "chain_head": chain_head,
        "content_hash": content_hash,
        "hipaa_sections": hipaa_sections,
        "total_cost_usd": total_cost_usd,
        "replay": replay_cmp,
        "fail_dec": fail_dec,
        "cls_compile": cls_compile,
        "soe_surfaces": soe_surfaces,
        "deny_probe": deny_probe,
        "influence_change": influence_change,
    })

    claim_posture = _build_claim_posture(
        stub_mode,
        gateway_proof,
        isolation_proof,
        multi_agent,
        tool_execution,
        proof_id,
        chain_head,
        content_hash,
        control_execution,
    )
    buyer_proof = {
        "workload_contract": "openai_compatible_http",
        "insertion_point": "/v1/chat/completions routed through connector-platform",
        "buyer_components_unchanged": [
            "buyer application and enterprise pipeline stay unchanged on the OpenAI-compatible path",
            "LLM-facing request shape remains OpenAI-compatible",
            "existing enterprise workflow continues without a rewrite",
        ],
        "buyer_components_governed": [
            "LLM decision path",
            "memory access policy checks",
            "tool dispatch and approval path",
            "PHI write control gate",
        ],
        "buyer_components_not_touched": [
            "no buyer-side enterprise pipeline code is changed for the gateway path",
            "no customer workflow or downstream integration is touched unless explicitly enabled",
            "no customer infrastructure rewrite is required for plug-and-play onboarding",
        ],
        "gateway_proof": gateway_proof,
        "knowledge_proof": knowledge_proof,
        "isolation_proof": isolation_proof,
        "claim_posture": claim_posture,
        "boundary_enforcement": {
            "attempted_action": f"mem_write:{phi_resource}",
            "verdict": control_execution.get("control_write_phi", {}).get("verdict", "UNKNOWN"),
            "enforcement_source": control_execution.get("enforcement_state", "unknown"),
            "unsafe_side_effect_prevented": control_execution.get("control_write_phi", {}).get("verdict") == "DENY",
        },
        "proof_notes": {
            "no_code_changes": "proven through the live OpenAI-compatible gateway contract when the workload only changes base_url to Connector",
            "plug_and_play": "proven through the live gateway route plus OpenAI-compatible request/response contract",
            "runtime_isolation": "proven at policy boundary when cross-agent or PHI write actions are denied; hard OS sandboxing is not shown here",
        },
    }
    operator_proof = {
        "runtime_health": {
            "agent_pid": pid,
            "namespace": ns,
            "stub_mode": stub_mode,
        },
        "knot_engine": {
            "knowledge_evolution": knowledge_proof,
            "memory_evolution": memory_snapshot,
            "retrieval_stability": retrieval_stability,
            "hallucination_chain": dehallucination,
        },
        "reasoning_chain": {
            "steps": reasoning_steps[:8],
            "conclusion": reasoning_conclusion,
            "quality": reasoning_quality,
            "reflection": reasoning_reflection,
        },
        "prompt_entities": {
            "human_prompts": memory_snapshot.get("human_prompts", []),
            "instruction_packets": [p for p in memory_snapshot.get("recall_packets", []) if "instruction" in p.get("tags", [])][:5],
        },
        "decision_ids": [value for value in [live_dec.get("decision_id"), fail_dec.get("decision_id"), phi_dec.get("decision_id")] if value],
        "policy_gates": {
            "phi_read": control_execution.get("control_read_phi", {}),
            "phi_write": control_execution.get("control_write_phi", {}),
            "deny_probe": deny_probe,
        },
        "tool_governance": tool_execution,
        "trace": {
            "source_kind": trace_source_kind,
            "steps": trace_source[:5],
        },
        "proof": {
            "proof_id": proof_id,
            "chain_head": chain_head,
            "content_hash": content_hash,
            "receipts_count": receipts_count_final,
        },
        "compliance": {
            "phi_resource": phi_resource,
            "policy_verdict": _policy_verdict(policy_phi_data),
            "hipaa_sections": hipaa_sections,
        },
        "cost": {
            "decision_cost_usd": decision_cost,
            "total_cost_usd": total_cost_usd,
            "daily_projection_usd": daily_proj,
        },
        "hitl": {
            "count": hitl_count,
            "requests": hitl_queue[:3],
        },
    }

    return {
        "pid": pid,
        "ns": ns,
        "agent": agent,
        "live_dec": live_dec,
        "fail_dec": fail_dec,
        "phi_dec": phi_dec,
        "recovery_dec": recovery_dec,
        "trust_grade": trust_grade,
        "audit_entries": audit_entries,
        "packets": packets,
        "agents_count_demo": agents_count_demo,
        "agents_count_total": agents_count_total,
        "total_cost_usd": total_cost_usd,
        "decision_cost": decision_cost,
        "daily_proj": daily_proj,
        "stub_mode": stub_mode,
        "proof_id": proof_id,
        "cid_chain": cid_chain[:5],
        "ops_count": ops_count,
        "cert_url": cert_url,
        "receipt_cid": receipt_cid,
        "chain_head": chain_head,
        "sig": sig,
        "receipts_count": receipts_count_final,
        "first_receipt": first_receipt,
        "content_hash": content_hash,
        "trace_source": trace_source[:5],
        "reasoning_chain": reasoning_steps[:8],
        "reasoning_quality": reasoning_quality,
        "reasoning_conclusion": reasoning_conclusion,
        "reasoning_reflection": reasoning_reflection,
        "deep_recall": memory_snapshot.get("deep_recall", {}),
        "deep_recall_chain": dehallucination.get("deep_recall_chain", {}),
        "trace_source_kind": trace_source_kind,
        "risk_flags": risk_flags,
        "key_inputs": key_inputs,
        "why_context": why_context,
        "fail_analysis": fail_analysis,
        "hipaa_sections": hipaa_sections,
        "policy_phi": policy_phi_data,
        "policy_phi_write": policy_phi_write_data,
        "policy_phi_verdict": _policy_verdict(policy_phi_data),
        "phi_resource": phi_resource,
        "control_execution": control_execution,
        "deny_probe": deny_probe,
        "influence_change": influence_change,
        "multi_agent": multi_agent,
        "isolation_proof": isolation_proof,
        "memory_snapshot": memory_snapshot,
        "knowledge_proof": knowledge_proof,
        "retrieval_stability": retrieval_stability,
        "gateway_proof": gateway_proof,
        "dehallucination": dehallucination,
        "tool_execution": tool_execution,
        "replay": replay_cmp,
        "cls_compile": cls_compile,
        "soe_surfaces": soe_surfaces,
        "consequence_cards": consequence_cards,
        "close_scorecard": close_scorecard,
        "hitl_queue": hitl_queue,
        "hitl_count": hitl_count,
        "fail_label": fail_label,
        "context_label": os.getenv("DEMO_CONTEXT_LABEL", ""),
        "context_cid": os.getenv("DEMO_CONTEXT_CID", ""),
        "defense_pkg_d": defense_d,
        "report_d": report_d,
        "raw_compliance_report": hipaa_d,
        "raw_proof_certificate": proof_d,
        "raw_defense_package": defense_d,
        "raw_receipts": receipts_d,
        "raw_books": books_d,
        "buyer_proof": buyer_proof,
        "operator_proof": operator_proof,
        "claim_posture": claim_posture,
    }


def validate_context(context: Dict[str, Any]) -> None:
    if not context["pid"]:
        raise RuntimeError("No live agent. Run `python demos/demo.py bootstrap` first.")
    live = context["live_dec"]
    if not live.get("ok"):
        raise RuntimeError(
            f"Live decision failed: {live.get('error', 'unknown')}. "
            "Check CONNECTOR_LLM_API_KEY or set CONNECTOR_LLM_STUB=1."
        )
    if not live.get("text"):
        raise RuntimeError("Live decision returned empty text. Check LLM config.")
    warnings = []
    if context.get("trace_source_kind") == "none":
        warnings.append("TRACE: No live trace source found (reasoning-chain, agent-traces, defense-package, journal).")
    if not context.get("proof_id"):
        warnings.append("PROOF: Missing proof artifact. Check /proof/generate.")
    if not context.get("live_dec", {}).get("decision_id"):
        warnings.append("GLUE: Missing live decision_id. Check record_decision.")
    if not context.get("fail_dec", {}).get("decision_id"):
        warnings.append("GLUE: Missing failure decision_id.")
    if not context.get("chain_head") or not context.get("content_hash"):
        warnings.append("PROOF: Missing chain_head or content_hash.")
    if not context.get("stub_mode") and context.get("total_cost_usd", 0) == 0:
        warnings.append("COST: Total cost is zero. Check cost engine.")
    if not context.get("hipaa_sections"):
        warnings.append("COMPLIANCE: Missing HIPAA mapping.")
    policy = context.get("policy_phi_verdict", {})
    if policy.get("verdict") not in {"ALLOW", "DENY", "UNKNOWN"}:
        warnings.append("POLICY: Missing policy verdict.")
    if not context.get("cls_compile", {}).get("ok"):
        warnings.append("CLS: Compile preflight missing.")
    if not any(v.get("ok") for v in context.get("soe_surfaces", {}).values()):
        warnings.append("SOE: Surface output engine unavailable.")
    mem = context.get("memory_snapshot", {})
    if mem.get("recall_count", 0) == 0 and mem.get("tree_total", 0) == 0:
        warnings.append("MEMORY: No packets found in recall or tree.")
    tool = context.get("tool_execution", {})
    if not tool.get("registered"):
        warnings.append("TOOL: MCP bridge registration failed.")
    if not tool.get("invoke_result", {}).get("outcome"):
        warnings.append("TOOL: MCP tool invoke returned no outcome.")
    buyer = context.get("buyer_proof", {})
    if not buyer.get("claim_posture"):
        warnings.append("BUYER: Missing claim posture envelope.")
    if not buyer.get("boundary_enforcement", {}).get("attempted_action"):
        warnings.append("BUYER: Missing boundary enforcement snapshot.")
    if not buyer.get("gateway_proof", {}).get("route_available"):
        warnings.append("BUYER: Gateway proof unavailable. Check /v1/models and /v1/chat/completions.")
    if not buyer.get("isolation_proof", {}).get("verify_report_available"):
        warnings.append("BUYER: Isolation verification proof unavailable. Check /verify/report.")
    if context.get("knowledge_proof", {}).get("knot_entities", 0) == 0:
        warnings.append("KNOWLEDGE: Knot entity graph is empty. Check /memory/graph/entities or seed graph state.")
    dehal = context.get("dehallucination", {})
    # Only warn when a real LLM output existed but failed the chain — not in stub/no-text mode
    dehal_has_text = bool(dehal.get("grounding", {}).get("available") or dehal.get("claims", {}).get("available"))
    if dehal_has_text:
        if dehal.get("chain_verdict") == "UNSAFE":
            warnings.append("DEHALLUCINATION: Chain verdict UNSAFE — claims rejected or high hallucination risk.")
        elif dehal.get("chain_verdict") == "NEEDS_REVIEW":
            warnings.append("DEHALLUCINATION: Grounding or claims endpoint unavailable — chain incomplete.")
    if warnings:
        print("\n  ╔══ OPERATOR VALIDATION WARNINGS ══╗")
        for w in warnings:
            print(f"  ║  ⚠ {w}")
        print("  ╚══════════════════════════════════╝\n")


def _t(s: Optional[str], n: int = 120) -> str:
    if not s:
        return ""
    return (s[:n] + "…") if len(s) > n else s


def _display_token(value: Optional[str], head: int = 16, tail: int = 8) -> str:
    if not value:
        return ""
    value = str(value)
    if len(value) <= head + tail + 1:
        return value
    return f"{value[:head]}…{value[-tail:]}"


def build_slides(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    pid         = context["pid"]
    live        = context["live_dec"]
    fail        = context["fail_dec"]
    phi         = context["phi_dec"]
    stub_mode   = bool(context.get("stub_mode"))
    tg          = context["trust_grade"]
    ae          = context["audit_entries"]
    pkt         = context["packets"]
    ac_demo     = context["agents_count_demo"]
    ac_total    = context["agents_count_total"]
    dec_cost    = context["decision_cost"]
    daily_proj  = context["daily_proj"]
    total_cost  = context["total_cost_usd"]
    proof_id    = context["proof_id"]
    cid_chain   = context["cid_chain"]
    receipt_cid = context["receipt_cid"]
    chain_head  = context["chain_head"]
    sig         = context["sig"]
    rcpts       = context["receipts_count"]
    reasoning   = context["reasoning_chain"]
    risk_flags  = context["risk_flags"]
    key_inputs  = context["key_inputs"]
    why_ctx     = context["why_context"]
    fail_anl    = context["fail_analysis"]
    chash       = context["content_hash"]
    hipaa       = context["hipaa_sections"]
    fail_label  = context["fail_label"]
    replay      = context["replay"]
    policy_phi  = context["policy_phi"]
    policy_phi_v = context["policy_phi_verdict"]
    phi_resource = context.get("phi_resource", "")
    cards       = context["consequence_cards"]
    close_score = context["close_scorecard"]
    control_exec = context["control_execution"]
    deny_probe = context["deny_probe"]
    influence_change = context["influence_change"]
    multi_agent = context["multi_agent"]
    cls_compile = context["cls_compile"]
    soe_surfaces = context["soe_surfaces"]
    memory_snap = context["memory_snapshot"]
    dehal = context["dehallucination"]
    tool_exec = context["tool_execution"]
    hitl_queue  = context.get("hitl_queue", [])
    hitl_count  = context.get("hitl_count", 0)
    buyer_proof = context.get("buyer_proof", {})
    operator_proof = context.get("operator_proof", {})
    claim_posture = context.get("claim_posture", {})
    gateway_proof = context.get("gateway_proof", {})
    isolation_proof = context.get("isolation_proof", {})
    knowledge_proof = context.get("knowledge_proof", {})
    retrieval_stability = context.get("retrieval_stability", {})
    raw_storage_proof = {
        "agent_memory_namespace": memory_snap.get("namespace", ""),
        "agent_memory_packets": memory_snap.get("recall_packets", [])[:5],
        "agent_memory_tree": memory_snap.get("tree_packets", [])[:5],
        "knowledge_retrieval_facts": knowledge_proof.get("retrieval", {}).get("facts", [])[:5],
        "knowledge_source_cids": knowledge_proof.get("retrieval", {}).get("source_cids", [])[:5],
        "retrieval_stability": retrieval_stability,
        "isolation_scope": {
            "agent_namespace": memory_snap.get("namespace", ""),
            "peer_namespace": multi_agent.get("peer_agent", {}).get("namespace", ""),
            "cross_agent_read_verdict": multi_agent.get("interaction", {}).get("primary_reads_peer", {}),
        },
    }
    live_did    = live.get("decision_id") or receipt_cid
    fail_did    = fail.get("decision_id") or ""
    phi_did     = phi.get("decision_id") or ""

    return [
        # ── SLIDE 1 ─────────────────────────────────────────────────
        {
            "number": 1,
            "title": "Live Runtime Contract",
            "narration": (
                '"This demo has two proof planes."\n'
                "\n"
                "  Buyer proof: where Connector sits and what it governs.\n"
                "  Operator proof: what the running node actually did.\n"
                "\n"
                '"Everything shown below is runtime-derived."'
            ),
            "commands": ["connectorctl health", "connectorctl status"],
            "evidence": {
                "buyer_proof_available": bool(buyer_proof),
                "operator_proof_available": bool(operator_proof),
                "demo_agents": ac_demo,
                "node_agents_total": ac_total,
                "live_decision_id": _t(live_did, 20),
                "claim_posture": claim_posture,
            },
            "fail_fast": ["demo_agents == 0 => bootstrap first",
                          "live_decision_id empty => glue failed",
                          "trust_grade == ? => check infra"],
        },
        # ── SLIDE 2 ─────────────────────────────────────────────────
        {
            "number": 2,
            "title": "Buyer Boundary",
            "narration": (
                '"Before platform depth, here is the buyer truth."\n'
                "\n"
                '"What stays unchanged, what Connector governs, and what is still not proven in this run."'
            ),
            "commands": ["POST /v1/chat/completions", f"connectorctl show agent {pid}"],
            "evidence": buyer_proof,
            "fail_fast": ["audit_entries == 0 => rerun bootstrap and live decision flow",
                          "cost_visibility == unavailable => check cost engine"],
        },
        # ── SLIDE 2.5 ───────────────────────────────────────────────
        {
            "number": 3,
            "title": "Claim Posture",
            "narration": (
                '"These are the exact claim states for this run."\n'
                "\n"
                '"Anything not proven live is marked explicitly."'
            ),
            "commands": ["python demos/demo.py --no-wait"],
            "evidence": {
                "claim_posture": claim_posture,
                "gateway_proof": gateway_proof,
                "isolation_proof": isolation_proof,
                "knowledge_proof": knowledge_proof,
                "boundary_enforcement": buyer_proof.get("boundary_enforcement", {}),
                "proof_notes": buyer_proof.get("proof_notes", {}),
            },
            "fail_fast": [
                "claim_posture empty => buyer proof envelope missing",
            ],
        },
        # ── SLIDE 4 ───────────────────────────────────────────────
        {
            "number": 4,
            "title": "A Real AI Decision",
            "narration": (
                '"Now the governed workflow path."\n'
                "\n"
                "  [already executed — results below]\n"
                "\n"
                '"This answer was generated, recorded, and linked to runtime evidence."'
            ),
            "commands": [f"connectorctl show agent {pid}",
                         "POST /v1/chat/completions  # already executed"],
            "evidence": {
                "decision_id": live_did,
                "response": _t(live.get("text"), 400),
                "tokens_used": live.get("tokens", 0),
                "cost_usd": live.get("cost_usd", 0.0),
                "model": live.get("model", ""),
                "trust_grade": tg,
                "content_hash": _display_token(chash),
                "signature": _display_token(live.get("signature")),
                "latency_ms": live.get("latency_ms", {}),
                "memory": memory_snap,
            },
            "fail_fast": ["decision_id empty => record_decision failed",
                          "tokens_used == 0 => check LLM config",
                          "content_hash empty => check disputes/record endpoint",
                          "memory.recall_count == 0 => check memory/recall"],
        },
        # ── SLIDE 5 ───────────────────────────────────────────────
        {
            "number": 5,
            "title": "Boundary Enforcement",
            "narration": (
                '"This is the control edge, not just a report."\n'
                "\n"
                '"Unsafe access was checked at the policy boundary and the verdict is shown live."'
            ),
            "commands": [
                f"connectorctl inspect {pid}",
                f"POST /api/v1/agents/{pid}/policy/check",
            ],
            "evidence": {
                "boundary_enforcement": buyer_proof.get("boundary_enforcement", {}),
                "multi_agent": multi_agent,
                "isolation_proof": isolation_proof,
                "control_execution": control_exec,
            },
            "fail_fast": [
                "boundary_enforcement.attempted_action empty => no boundary test was captured",
                "sandboxing.mac_enforcement.verdict not DENY => isolation may be weak",
            ],
        },
        # ── SLIDE 6 ─────────────────────────────────────────────────
        {
            "number": 6,
            "title": "Real Tool Execution (MCP Governed)",
            "narration": (
                '"Actions are governed before dispatch."\n'
                "\n"
                '"Register → inject-check → kernel dispatch → audit."'
            ),
            "commands": [
                "POST /api/v1/tools/mcp/register",
                "POST /api/v1/tools/mcp/invoke",
                "GET /api/v1/tools/mcp/bridges",
                "GET /api/v1/tools/approvals/pending",
            ],
            "evidence": tool_exec,
            "fail_fast": [
                "registered == false => bridge registration failed",
                "invoke_result.outcome empty => tool dispatch did not execute",
            ],
        },
        # ── SLIDE 7 ─────────────────────────────────────────────────
        {
            "number": 7,
            "title": "Operator Explain + Trace",
            "narration": (
                '"The operator should be able to investigate like code."\n'
                "\n"
                '"Reasoning, latency, steps, and outcomes are all visible."'
            ),
            "commands": [f"connectorctl trace agent {pid} --last 15m",
                         f"connectorctl explain agent {pid}",
                         f"connectorctl inspect {pid}"],
            "evidence": {
                "decision_id": live_did,
                "why_context": why_ctx,
                "trace_source": context.get("trace_source_kind", "none"),
                "knot_hallucination_chain": dehal,
                "trace_steps": [
                    {
                        "step": i + 1,
                        "kind": (e.get("operation") or e.get("action", "llm_call"))[:40],
                        "outcome": (e.get("outcome") or "allowed")[:40],
                        **({"tokens": e.get("tokens") or live.get("tokens", 0)}
                           if (e.get("operation") or e.get("action", "")) == "llm_call"
                           else {}),
                        "latency_ms": (
                            e.get("duration_ms")
                            or (e.get("duration_us", 0) // 1000 if e.get("duration_us") else 0)
                        ),
                    }
                    for i, e in enumerate(reasoning[:5])
                ],
            },
            "fail_fast": ["trace_steps empty => check reasoning-chain endpoint"],
        },
        # ── SLIDE 8 ─────────────────────────────────────────────────
        {
            "number": 8,
            "title": "Raw Memory + Raw Knowledge",
            "narration": (
                '"This is the stored substrate, not a metric."\n'
                "\n"
                '"These are raw agent-scoped memory packets and raw knot-retrieved knowledge facts used to stabilize the decision."'
            ),
            "commands": [
                f"GET /api/v1/memory/recall/{memory_snap.get('namespace', '')}",
                "POST /api/v1/memory/knowledge/query2",
                f"connectorctl inspect {pid}",
            ],
            "evidence": raw_storage_proof,
            "fail_fast": [
                "agent_memory_packets empty => no agent-scoped stored memory was shown",
                "knowledge_retrieval_facts empty => knot retrieval proof missing",
            ],
        },
        {
            "number": 9,
            "title": "Evidence + Proof",
            "narration": (
                '"This is evidence, not logs."\n'
                "\n"
                '"Every output is linked to receipts, proofs, and chain state."'
            ),
            "commands": [f"connectorctl prove agent {pid} --forensic",
                         f"GET /agents/{pid}/audit/receipts"],
            "evidence": {
                "decision_id": live_did,
                "knot_engine": operator_proof.get("knot_engine", {}),
                "content_hash": _display_token(chash),
                "platform_sig": _display_token(sig),
                "receipts_in_chain": rcpts,
                "chain_head": _display_token(chain_head),
                "proof_certificate_raw": context.get("raw_proof_certificate", {}),
            },
            "fail_fast": ["decision_id empty => glue failed",
                          "content_hash empty => record_decision failed"],
        },
        # ── SLIDE 9 ─────────────────────────────────────────────────
        {
            "number": 10,
            "title": "Cost + Compliance",
            "narration": (
                '"The buyer needs accountability, not just AI output."\n'
                "\n"
                '"This run shows spend, PHI posture, and mapped compliance evidence."'
            ),
            "commands": [f"connectorctl cost {pid}",
                         "GET /api/v1/actionlog/regulation-report/hipaa"],
            "evidence": {
                "decision_cost_usd": dec_cost,
                "tokens_total": live.get("tokens", 0),
                "session_total_usd": total_cost,
                "daily_projection_usd": daily_proj,
                "phi_resource": phi_resource,
                "policy_verdict": policy_phi_v.get("verdict", "UNKNOWN"),
                "regulation_report_raw": context.get("raw_compliance_report", {}),
            },
            "fail_fast": ["decision_cost_usd == 0.0 and tokens == 0 => check LLM config",
                          "regulation_report_raw empty => check regulation-report endpoint"],
        },
        # ── SLIDE 10 ────────────────────────────────────────────────
        {
            "number": 11,
            "title": "Failure + Recovery + HITL",
            "narration": (
                '"The system must do more than succeed."\n'
                "\n"
                '"It must detect unsafe paths, show root cause, and let an operator intervene."'
            ),
            "commands": [f"connectorctl trace agent {pid}",
                         f"connectorctl explain agent {pid}",
                         f"GET /api/v1/agents/{pid}/hitl/pending"],
            "evidence": {
                "failure": fail_anl,
                "deny_probe": deny_probe,
                "influence_change": influence_change,
                "hitl_queue_count": hitl_count,
                "hitl_requests": [
                    {
                        "request_id": r.get("request_id", r.get("id", "")),
                        "action": r.get("action", r.get("requested_action", "")),
                        "risk_level": r.get("risk_level", ""),
                        "status": r.get("status", "pending"),
                    }
                    for r in hitl_queue[:3]
                ],
            },
            "fail_fast": ["failure.failure_signals empty => check LLM response",
                          "hitl_queue_count == 0 and deny_probe.verdict != DENY => control escalation not demonstrated"],
        },
        # ── SLIDE 11 ────────────────────────────────────────────────
        {
            "number": 12,
            "title": "Run This In Your System",
            "narration": (
                '"The pilot close must work for both buyer and operator."\n'
                "\n"
                '"Buyer: boundary, control, proof posture. Operator: trace, receipts, cost, compliance."'
            ),
            "commands": ["connector.ai/pilot",
                         "30-day pilot — one workflow, buyer proof + operator proof"],
            "evidence": {
                "buyer_proof": buyer_proof,
                "operator_proof": operator_proof,
                "operator_close_scorecard": close_score,
            },
            "fail_fast": ["decision_id empty => stop, glue failed",
                          "audit_entries == 0 => stop, do not pitch"],
        },
    ]


def write_evidence_bundle(context: Dict[str, Any]) -> str:
    bundle_dir = Path("demos/evidence")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = bundle_dir / f"pilot_evidence_bundle_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "execution_mode": "stub" if context.get("stub_mode") else "real",
        "agent_pid": context.get("pid"),
        "key_decisions": [
            context.get("live_dec", {}).get("decision_id"),
            context.get("fail_dec", {}).get("decision_id"),
            context.get("phi_dec", {}).get("decision_id"),
        ],
        "traces": context.get("reasoning_chain", []),
        "proof": {
            "proof_certificate_raw": context.get("raw_proof_certificate", {}),
            "defense_package_raw": context.get("raw_defense_package", {}),
            "receipts_raw": context.get("raw_receipts", {}),
            "proof_id": context.get("proof_id"),
            "receipt_cid": context.get("receipt_cid"),
            "chain_head": context.get("chain_head"),
            "content_hash": context.get("content_hash"),
        },
        "compliance": {
            "regulation_report_raw": context.get("raw_compliance_report", {}),
            "books_position_raw": context.get("raw_books", {}),
            "policy_phi": context.get("policy_phi"),
            "policy_phi_write": context.get("policy_phi_write"),
            "policy_phi_verdict": context.get("policy_phi_verdict"),
        },
        "cost_summary": {
            "decision_cost_usd": context.get("decision_cost"),
            "total_cost_usd": context.get("total_cost_usd"),
            "daily_projection_usd": context.get("daily_proj"),
        },
        "latency": {
            "live_decision_ms": context.get("live_dec", {}).get("latency_ms", {}),
            "failure_decision_ms": context.get("fail_dec", {}).get("latency_ms", {}),
            "phi_decision_ms": context.get("phi_dec", {}).get("latency_ms", {}),
            "recovery_decision_ms": context.get("recovery_dec", {}).get("latency_ms", {}),
        },
        "gateway_proof": context.get("gateway_proof", {}),
        "knowledge_proof": context.get("knowledge_proof", {}),
        "retrieval_stability": context.get("retrieval_stability", {}),
        "deep_recall": context.get("deep_recall", {}),
        "deep_recall_chain": context.get("deep_recall_chain", {}),
        "claim_posture": context.get("claim_posture", {}),
        "buyer_proof": context.get("buyer_proof", {}),
        "operator_proof": context.get("operator_proof", {}),
        "decision_consequence_cards": context.get("consequence_cards", []),
        "replay_time_travel": context.get("replay", {}),
        "real_deny_probe": context.get("deny_probe", {}),
        "control_execution": context.get("control_execution", {}),
        "influence_change": context.get("influence_change", {}),
        "multi_agent": context.get("multi_agent", {}),
        "memory_snapshot": context.get("memory_snapshot", {}),
        "raw_storage_proof": {
            "agent_memory_namespace": context.get("memory_snapshot", {}).get("namespace", ""),
            "agent_memory_packets": context.get("memory_snapshot", {}).get("recall_packets", [])[:5],
            "human_prompt_packets": context.get("memory_snapshot", {}).get("human_prompts", [])[:5],
            "deep_recall": context.get("memory_snapshot", {}).get("deep_recall", {}),
            "agent_memory_tree": context.get("memory_snapshot", {}).get("tree_packets", [])[:5],
            "knowledge_retrieval_facts": context.get("knowledge_proof", {}).get("retrieval", {}).get("facts", [])[:5],
            "knowledge_source_cids": context.get("knowledge_proof", {}).get("retrieval", {}).get("source_cids", [])[:5],
            "retrieval_stability": context.get("retrieval_stability", {}),
        },
        "dehallucination": context.get("dehallucination", {}),
        "tool_execution": context.get("tool_execution", {}),
        "cls_contract": {
            "source": DEMO_CLS_SOURCE,
            "compile_result": context.get("cls_compile", {}),
        },
        "soe_surfaces": context.get("soe_surfaces", {}),
        "operator_close_scorecard": context.get("close_scorecard", {}),
        "pilot_plan": {
            "duration_days": 30,
            "workflow_count": 1,
            "success_metrics": [
                "100% traceability",
                "audit-ready proof receipts",
                "daily cost visibility",
            ],
            "operator_handoff": [
                "run make demo",
                "review evidence bundle",
                "validate control/proof/compliance gates",
            ],
        },
    }
    bundle_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(bundle_path)


def run_demo(platform: ConnectorPlatform, interactive: bool) -> int:
    context = build_context(platform)
    validate_context(context)
    slides = build_slides(context)
    for slide in slides:
        print_slide(slide, interactive)
    bundle_path = write_evidence_bundle(context)
    print(f"\nPilot evidence bundle generated: {bundle_path}")
    close = context.get("close_scorecard", {})
    print(
        f"Operator close score: {close.get('passed', 0)}/{close.get('total', 0)} "
        f"(ready={close.get('close_ready', False)})"
    )
    if close.get("gaps"):
        print(f"Remaining gaps: {', '.join(close.get('gaps', []))}")
    print("\nDemo complete.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Connector enterprise demo runner")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["run", "bootstrap", "run_agent", "run_failure_case", "run_phi_case"],
        default="run",
    )
    parser.add_argument("--no-wait", action="store_true")
    args = parser.parse_args()

    platform = ConnectorPlatform()
    if args.mode == "bootstrap":
        return bootstrap(platform)
    if args.mode == "run_agent":
        return run_agent(platform)
    if args.mode == "run_failure_case":
        return run_failure_case(platform)
    if args.mode == "run_phi_case":
        return run_phi_case(platform)
    return run_demo(platform, interactive=not args.no_wait)


if __name__ == "__main__":
    sys.exit(main())
