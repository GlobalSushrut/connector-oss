#!/usr/bin/env python3
"""
Connector Platform — Infrastructure Demo
10 slides demonstrating the 7 core infrastructure services

This is a horizontal AI infrastructure platform demo, NOT healthcare SaaS.
Healthcare is ONE proof domain among many.

The 7 Infrastructure Services:
1. Agent Isolation
2. Memory Dehallucination
3. Secure Tool Execution
4. Debugging & Explainability
5. Cost Control
6. Audit Trail
7. Compliance Reporting

Usage:
    python infrastructure_demo.py           # all slides
    python infrastructure_demo.py 3         # single slide
    python infrastructure_demo.py 1 5       # range
"""

import sys
import json
from llm import DeepSeekLLM
from system_data import ConnectorPlatform

llm = DeepSeekLLM()
platform = ConnectorPlatform()


def slide_1_infrastructure_positioning():
    """Slide 1: Infrastructure Positioning - Demonstrating Memory Dehallucination"""
    
    # STEP 1: Retrieve Connector overview
    kb_overview = platform.search_memory(
        ns="k/connector",
        query="Connector control plane AI agents infrastructure",
        top_k=2
    )
    
    # STEP 2: Retrieve each service individually from k/connector/service namespace
    service_queries = [
        "agent isolation MAC Bell-LaPadula Biba multi-tenant",
        "memory dehallucination CID BM25 grounded retrieval",
        "secure tool execution guard pipeline policy enforcement",
        "debugging explainability cognitive substrate reasoning trace",
        "cost control token metering budget enforcement ledger",
        "audit trail HMAC journal chain verification tamper-proof",
        "compliance reporting HIPAA EU AI Act SOC2 regulatory"
    ]
    
    all_services = []
    for query in service_queries:
        result = platform.search_memory(
            ns="k/connector/service",
            query=query,
            top_k=1
        )
        if result.get("results"):
            all_services.append(result["results"][0])
    
    retrieval_status = "RETRIEVED" if len(all_services) >= 7 else "PARTIAL"
    
    # STEP 3: LLM generates positioning using retrieved sources with citations
    prompt = f"""You are presenting Connector. Use the retrieved knowledge base sources. Cite CIDs and BM25 scores.

Retrieved Overview:
{json.dumps(kb_overview.get('results', [])[:2], indent=2)}

Retrieved Services (all 7):
{json.dumps(all_services, indent=2)}

Write 300 words positioning Connector as the control plane for AI agents:

1. Opening: Production AI governance challenges (isolation, hallucination, tool safety, explainability, cost, audit, compliance)
2. The 7 Services: List each service with its key capability. Cite CID and BM25 score for each.
   Format: "**Service Name**: [capability] (Source: CID <cid>, score: <score>)"
3. Platform Statement: Cite overview CID
4. Cross-domain applicability: healthcare, finance, legal, customer service

Be specific. Use Connector terminology (MAC, CID, HMAC, guard pipeline, cognitive substrate). Every service MUST have a citation."""

    result = llm.generate(prompt, max_tokens=600)
    
    return {
        "slide": 1,
        "title": "Connector: The Control Plane for AI Agents",
        "service": "platform_positioning_with_retrieval",
        "retrieval_proof": {
            "overview_search": {
                "query": "Connector control plane AI agents infrastructure",
                "algorithm": kb_overview.get("algorithm"),
                "result_count": kb_overview.get("result_count", 0),
                "top_score": kb_overview.get("results", [{}])[0].get("score") if kb_overview.get("results") else 0
            },
            "services_retrieved": {
                "total_services": len(all_services),
                "expected_services": 7,
                "retrieval_status": retrieval_status,
                "service_scores": [s.get("score") for s in all_services]
            }
        },
        "content_with_citations": result["content"],
        "kb_sources": {
            "overview": kb_overview.get("results", [])[:2],
            "services": all_services
        },
        "the_7_services": [
            "Agent Isolation",
            "Memory Dehallucination",
            "Secure Tool Execution",
            "Debugging & Explainability",
            "Cost Control",
            "Audit Trail",
            "Compliance Reporting"
        ],
        "positioning": "Control plane for production AI agents (proven via knowledge retrieval)",
        "cross_domain": ["healthcare", "finance", "legal", "customer_service"],
        "meta": result["meta"]
    }


def slide_2_seven_services():
    """Slide 2: The 7 Services - Compact Live Proof"""

    books = platform.get_books_position()
    agents = platform.list_agents()
    journal = platform.get_books_journal(limit=5)

    resources = books.get("data", {}).get("resources", {})
    integrity = books.get("data", {}).get("integrity", {})

    service_specs = [
        ("Agent Isolation", "agent isolation MAC Bell-LaPadula Biba multi-tenant"),
        ("Memory Dehallucination", "memory dehallucination CID BM25 grounded retrieval"),
        ("Secure Tool Execution", "secure tool execution guard pipeline policy enforcement"),
        ("Debugging & Explainability", "debugging explainability cognitive substrate reasoning trace"),
        ("Cost Control", "cost control token metering budget enforcement ledger"),
        ("Audit Trail", "audit trail HMAC journal chain verification tamper-proof"),
        ("Compliance Reporting", "compliance reporting HIPAA EU AI Act SOC2 regulatory"),
    ]

    retrieved_services = []
    for service_name, query in service_specs:
        kb = platform.search_memory("k/connector/service", query, top_k=1)
        top = kb.get("results", [])
        retrieved_services.append({
            "service": service_name,
            "query": query,
            "source": top[0] if top else None,
        })

    compact_evidence = {
        "running_agents": agents.get("total_agents", 0),
        "healthy_agents": agents.get("healthy", 0),
        "active_memory_count": resources.get("active_memory_count", 0),
        "journal_entries": len(journal.get("entries", [])),
        "chain_length": integrity.get("chain_length", 0),
        "chain_verified": integrity.get("chain_verified", False),
        "trust_score": integrity.get("trust_score", 0),
        "trust_grade": integrity.get("trust_grade", "N/A"),
    }

    prompt = f"""You are presenting slide 2 of the Connector demo.

Write a compact 220-word service map.

Rules:
- Use the exact 7 services below.
- For each service: say what it is, which Connector component provides it, and cite the CID + BM25 score from the retrieved source.
- Tie each service to one live platform metric from the evidence block.
- Keep it crisp and product-like, not essay-like.

Retrieved service definitions:
{json.dumps(retrieved_services, indent=2)}

Live platform evidence:
{json.dumps(compact_evidence, indent=2)}

Format each line like:
**Service** — capability. Live proof: <metric>. Source: CID <cid>, score <score>.
"""

    result = llm.generate(prompt, max_tokens=500)

    services_with_evidence = [
        {"service": "Agent Isolation", "evidence": f"{agents.get('total_agents', 0)} agents running"},
        {"service": "Memory Dehallucination", "evidence": f"{resources.get('active_memory_count', 0)} memory packets"},
        {"service": "Secure Tool Execution", "evidence": f"{len(journal.get('entries', []))} signed journal entries"},
        {"service": "Debugging & Explainability", "evidence": f"{len(journal.get('entries', []))} recent operations traced"},
        {"service": "Cost Control", "evidence": "books ledger available"},
        {"service": "Audit Trail", "evidence": f"chain length {integrity.get('chain_length', 0)}"},
        {"service": "Compliance Reporting", "evidence": f"trust score {integrity.get('trust_score', 0)}/100"},
    ]

    return {
        "slide": 2,
        "title": "The 7 Services - Compact Live Proof",
        "service": "architecture_with_proof",
        "explanation": result["content"],
        "compact_platform_evidence": compact_evidence,
        "retrieved_service_sources": retrieved_services,
        "services_with_evidence": services_with_evidence,
        "meta": result["meta"]
    }


def slide_3_live_system_proof():
    """Slide 3: Live Runtime Proof + LLM Operator Brief"""

    books = platform.get_books_position()
    journal = platform.get_books_journal(limit=5)
    agents = platform.list_agents()
    resources = books.get('data', {}).get('resources', {})
    integrity = books.get('data', {}).get('integrity', {})

    proof_snapshot = {
        "running_agents": agents.get('total_agents', 0),
        "healthy_agents": agents.get('healthy', 0),
        "active_memory_count": resources.get('active_memory_count', 0),
        "active_memory_bytes": resources.get('active_memory_bytes', 0),
        "journal_entries": len(journal.get('entries', [])),
        "chain_length": integrity.get('chain_length', 0),
        "chain_verified": integrity.get('chain_verified', False),
        "reconciliation_status": integrity.get('reconciliation_status', books.get('meta', {}).get('reconciliation_status', 'UNKNOWN')),
        "trust_score": integrity.get('trust_score', 0),
        "trust_grade": integrity.get('trust_grade', 'N/A'),
        "fleet_cost_usd": agents.get('total_fleet_cost_usd', 0.0),
    }

    raw_evidence_sample = {
        "agents": [{
            "pid": a.get('pid'),
            "name": a.get('name'),
            "namespace": a.get('namespace'),
            "status": a.get('status'),
            "packets": a.get('metrics', {}).get('packets', 0),
            "recent_ops_1h": a.get('metrics', {}).get('recent_ops_1h', 0),
        } for a in agents.get('agents', [])[:3]],
        "journal_entries": [{
            "seq_no": e.get('seq_no'),
            "action": e.get('action'),
            "outcome": e.get('outcome'),
            "verification": e.get('verification'),
            "prev_hash": e.get('prev_hash'),
            "this_hash": e.get('this_hash'),
        } for e in journal.get('entries', [])[:3]],
    }

    service_sources = {
        "audit": platform.search_memory("k/connector/service", "audit trail HMAC journal chain verification tamper-proof", top_k=1),
        "debugging": platform.search_memory("k/connector/service", "debugging explainability cognitive substrate reasoning trace", top_k=1),
        "compliance": platform.search_memory("k/connector/service", "compliance reporting HIPAA EU AI Act SOC2 regulatory", top_k=1),
    }

    retrieved_sources = {
        key: value.get('results', [None])[0]
        for key, value in service_sources.items()
        if value.get('results')
    }

    prompt = f"""You are Connector's runtime copilot.

Using ONLY the live telemetry and retrieved service definitions below, write a compact 180-word operator brief for an executive audience.

Goals:
- Explain why this runtime is trustworthy.
- Call out the strongest proof signals.
- Mention one practical usable capability this platform enables right now.
- Include one clear operator recommendation.
- Cite CID and BM25 score when referring to Connector service concepts.

Live telemetry:
{json.dumps(proof_snapshot, indent=2)}

Retrieved service definitions:
{json.dumps(retrieved_sources, indent=2)}

Useful capability to highlight: convert raw kernel telemetry into an executive trust brief without hiding the underlying evidence.
"""

    operator_brief = llm.generate(prompt, max_tokens=350)

    return {
        "slide": 3,
        "title": "Live Runtime Proof + Operator Copilot",
        "service": "platform_telemetry_with_llm_interpretation",
        "description": "Real kernel telemetry plus an LLM-generated trust brief grounded in live evidence",
        "proof_snapshot": proof_snapshot,
        "trust_signals": [
            f"{proof_snapshot['healthy_agents']}/{proof_snapshot['running_agents']} agents healthy",
            f"{proof_snapshot['active_memory_count']} memory packets live",
            f"journal chain length {proof_snapshot['chain_length']}",
            f"chain verified = {proof_snapshot['chain_verified']}",
            f"trust score {proof_snapshot['trust_score']}/100 ({proof_snapshot['trust_grade']})",
        ],
        "raw_evidence_sample": raw_evidence_sample,
        "retrieved_service_sources": retrieved_sources,
        "usable_capability_showcase": {
            "capability": "LLM-generated executive runtime trust brief from live kernel telemetry",
            "content": operator_brief["content"],
            "meta": operator_brief["meta"],
        },
        "verification": {
            "data_source": "Real Connector kernel APIs",
            "no_simulation": True,
            "llm_grounded_in_live_telemetry": True,
            "timestamp": books.get('data', {}).get('generated_at_ms', 0)
        }
    }


def slide_4_agent_isolation():
    """Slide 4: Agent Isolation - Live Posture Review"""

    agents = platform.list_agents()
    cross_agent_map = platform.get_cross_agent_map()
    journal = platform.get_books_journal(limit=5)
    isolation_kb = platform.search_memory(
        "k/connector/service",
        "agent isolation MAC Bell-LaPadula Biba multi-tenant",
        top_k=1,
    )

    fleet = agents.get("agents", [])[:5]
    topology = cross_agent_map.get("agents", [])
    namespaces = [a.get("namespace") for a in topology if a.get("namespace")]
    shared_memories = sum(a.get("shared_memories", 0) for a in topology)

    namespace_counts = {}
    for namespace in namespaces:
        namespace_counts[namespace] = namespace_counts.get(namespace, 0) + 1

    duplicate_namespaces = [
        {"namespace": namespace, "agent_count": count}
        for namespace, count in namespace_counts.items()
        if count > 1
    ]

    posture_snapshot = {
        "running_agents": agents.get("total_agents", 0),
        "healthy_agents": agents.get("healthy", 0),
        "visible_namespaces": len(namespaces),
        "unique_namespaces": len(namespace_counts),
        "shared_memories": shared_memories,
        "duplicate_namespaces": duplicate_namespaces,
        "recent_notarized_entries": len([
            e for e in journal.get("entries", [])
            if e.get("verification") == "Notarized"
        ]),
    }

    live_evidence = {
        "fleet": [{
            "pid": a.get("pid"),
            "name": a.get("name"),
            "namespace": a.get("namespace"),
            "status": a.get("status"),
            "packets": a.get("metrics", {}).get("packets", 0),
        } for a in fleet],
        "cross_agent_map": topology,
        "journal_sample": [{
            "seq_no": e.get("seq_no"),
            "action": e.get("action"),
            "verification": e.get("verification"),
        } for e in journal.get("entries", [])[:3]],
        "service_source": isolation_kb.get("results", [])[:1],
    }

    prompt = f"""You are Connector's isolation copilot.

Using ONLY the live evidence below, write a compact 180-word isolation posture review.

Rules:
- Be honest: if namespaces are duplicated, say isolation is not fully clean yet.
- Explain what Connector's agent isolation service is supposed to provide using the retrieved source.
- Use live fleet topology and sharing state as proof.
- Mention one practical usable capability: detecting isolation drift or namespace collisions from runtime state.
- Include one concrete operator recommendation.
- Cite CID and BM25 score from the retrieved service source.

Isolation posture snapshot:
{json.dumps(posture_snapshot, indent=2)}

Live evidence:
{json.dumps(live_evidence, indent=2)}
"""

    result = llm.generate(prompt, max_tokens=350)

    return {
        "slide": 4,
        "title": "Agent Isolation - Live Posture Review",
        "service": "agent_isolation",
        "isolation_posture": posture_snapshot,
        "live_evidence": live_evidence,
        "usable_capability_showcase": {
            "capability": "LLM-generated isolation posture review from live agent topology",
            "content": result["content"],
            "meta": result["meta"],
        },
        "verification": {
            "data_source": "Real Connector agent and multiagent APIs",
            "read_only": True,
            "no_simulation": True,
            "llm_grounded_in_live_telemetry": True,
        },
        "cross_domain": ["finance", "legal", "customer_service"]
    }


def slide_5_memory_dehallucination():
    """Slide 5: Memory Dehallucination"""
    
    query = "chest pain HEART score"
    try:
        kb = platform.search_memory("k/medical", query, top_k=3)
    except Exception as e:
        kb = {"error": str(e), "result_count": 0, "results": []}
    
    status = "RETRIEVED" if kb.get("result_count", 0) > 0 else "SIMULATED"
    
    prompt = f"""Answer using retrieved sources. Cite CIDs.

Query: {query}
Sources: {json.dumps(kb.get("results", []), indent=2)}
Status: {status}

150 words with citations."""

    answer = llm.generate(prompt, max_tokens=300)
    
    explain_prompt = f"""Explain memory dehallucination service.

Evidence: Query returned {kb.get("result_count", 0)} results, status: {status}

Cover BM25, CID provenance, cross-domain use. 200 words."""

    explain = llm.generate(explain_prompt, max_tokens=400)
    
    return {
        "slide": 5,
        "service": "memory_dehallucination",
        "query": query,
        "kb_results": kb,
        "status": status,
        "answer": answer["content"],
        "explanation": explain["content"],
        "cross_domain": ["legal_research", "compliance", "policy_qa"],
        "meta": {"answer": answer["meta"], "explain": explain["meta"]}
    }


def slide_6_secure_tool_execution():
    """Slide 6: Secure Tool Execution - Unsafe Action Blocked"""

    journal = platform.get_books_journal(limit=10)
    topology = platform.get_cross_agent_map()
    service_kb = platform.search_memory(
        "k/connector/service",
        "secure tool execution guard pipeline policy enforcement",
        top_k=1,
    )

    kernel_pid = None
    if topology.get("agents"):
        kernel_pid = topology["agents"][0].get("pid")

    policy_preflight = platform.policy_check(
        kernel_pid or "pid:000003",
        "tool_dispatch",
        "mcp:demo:send_email",
    )

    governance_snapshot = {
        "policy_preflight_allowed": policy_preflight.get("allowed", False),
        "policy_preflight_reason": policy_preflight.get("reason"),
        "journal_entries_reviewed": len(journal.get("entries", [])),
    }

    live_evidence = {
        "attempted_action": policy_preflight.get("resource"),
        "preflight_decision": {
            "allowed": policy_preflight.get("allowed", False),
            "reason": policy_preflight.get("reason"),
            "detail": policy_preflight.get("detail"),
        },
        "control_flags": {
            "dispatch_blocked": not policy_preflight.get("allowed", False),
            "unsafe_action_prevented": not policy_preflight.get("allowed", False),
            "preflight_enforced": True,
        },
    }

    service_source = service_kb.get("results", [])[:1]
    source_summary = {
        "cid": service_source[0].get("cid") if service_source else None,
        "score": service_source[0].get("score") if service_source else None,
        "text_preview": service_source[0].get("text_preview") if service_source else None,
    }

    prompt = f"""You are Connector's tool governance copilot.

Using ONLY the live evidence below, write a 5-line operator summary.

Rules:
- Output exactly these labels and nothing else:
Status:
Attempted Action:
Reason:
Value:
Next Step:
- Use business-safe wording like misconfigured, blocked by policy, guard caught a gap.
- Do not say non-compliant.
- Value line should emphasize: prevents unauthorized high-risk actions before they reach external systems.

Governance snapshot:
{json.dumps(governance_snapshot, indent=2)}

Live evidence:
{json.dumps(live_evidence, indent=2)}

Retrieved service source summary:
{json.dumps(source_summary, indent=2)}
"""

    result = llm.generate(prompt, max_tokens=160)

    return {
        "slide": 6,
        "title": "Secure Tool Execution - Unsafe Action Blocked",
        "service": "secure_tool_execution",
        "governance_snapshot": governance_snapshot,
        "live_evidence": live_evidence,
        "usable_capability_showcase": {
            "capability": "LLM-generated secure tool execution review from live policy and tool-control state",
            "content": result["content"],
            "meta": result["meta"],
        },
        "verification": {
            "data_source": "Real Connector policy-check and tool APIs",
            "read_only": True,
            "no_simulation": True,
            "llm_grounded_in_live_telemetry": True,
        },
        "cross_domain": ["financial_transfers", "legal_signing", "refunds"],
    }


def slide_7_debugging_explainability():
    """Slide 7: Debugging & Explainability - Live Reasoning Chain"""

    agents = platform.list_agents()
    selected_agent = next(
        (a for a in agents.get("agents", []) if a.get("metrics", {}).get("packets", 0) > 0),
        agents.get("agents", [None])[0],
    )
    selected_pid = selected_agent.get("pid") if selected_agent else None
    agent_detail = platform.get_agent(selected_pid) if selected_pid else {}
    kernel_pid = agent_detail.get("meta", {}).get("kernel_pid")
    memory_tree = platform.get_agent_memory_tree(selected_pid) if selected_pid else {"tree": [], "total_packets": 0}
    reasoning_chain = platform.get_reasoning_chain(kernel_pid) if kernel_pid else {"audit_chain": []}
    service_kb = platform.search_memory(
        "k/connector/service",
        "debugging explainability cognitive substrate reasoning trace",
        top_k=1,
    )

    chain_entries = reasoning_chain.get("audit_chain", [])
    proof_snapshot = {
        "selected_agent": selected_agent.get("name") if selected_agent else None,
        "selected_agent_pid": selected_pid,
        "kernel_pid": kernel_pid,
        "memory_packets": memory_tree.get("total_packets", 0),
        "memory_sessions": memory_tree.get("session_count", 0),
        "reasoning_steps": len(chain_entries),
        "successful_steps": len([e for e in chain_entries if e.get("outcome") == "Success"]),
    }

    live_evidence = {
        "memory_tree_summary": {
            "namespace": memory_tree.get("namespace"),
            "total_packets": memory_tree.get("total_packets", 0),
            "session_count": memory_tree.get("session_count", 0),
        },
        "reasoning_chain_sample": [
            {
                "operation": e.get("operation"),
                "outcome": e.get("outcome"),
                "target_cid": e.get("target_cid"),
                "duration_us": e.get("duration_us"),
            }
            for e in chain_entries[:5]
        ],
        "service_source": service_kb.get("results", [])[:1],
    }

    prompt = f"""You are Connector's explainability copilot.

Using ONLY the live evidence below, write a 5-line operator summary.

Rules:
- Output exactly these labels and nothing else:
Status:
Agent:
Trace Depth:
Value:
Next Step:
- Keep it operational, not essay-like.
- Emphasize that the runtime exposes stepwise evidence instead of black-box output.
- Cite CID and BM25 score briefly if useful.

Proof snapshot:
{json.dumps(proof_snapshot, indent=2)}

Live evidence:
{json.dumps(live_evidence, indent=2)}
"""

    result = llm.generate(prompt, max_tokens=160)

    return {
        "slide": 7,
        "title": "Debugging & Explainability - Live Reasoning Chain",
        "service": "debugging_explainability",
        "proof_snapshot": proof_snapshot,
        "live_evidence": live_evidence,
        "usable_capability_showcase": {
            "capability": "LLM-generated explainability summary from live reasoning-chain evidence",
            "content": result["content"],
            "meta": result["meta"],
        },
        "verification": {
            "data_source": "Real Connector agent memory and reasoning-chain APIs",
            "read_only": True,
            "no_simulation": True,
            "llm_grounded_in_live_telemetry": True,
        },
        "cross_domain": ["credit_decisions", "legal_analysis", "fraud_detection"],
    }


def slide_8_cost_control():
    """Slide 8: Cost Control - Live Metering Posture"""

    ledger = platform.get_cost_breakdown()
    books = platform.get_books_position()
    agents = platform.list_agents()
    stats = llm.session_stats()
    service_kb = platform.search_memory(
        "k/connector/service",
        "cost control token metering budget enforcement ledger",
        top_k=1,
    )

    books_cost = books.get("data", {}).get("cost", {})
    recent_entries = books.get("data", {}).get("recent_entries", [])
    integrity = books.get("data", {}).get("integrity", {})
    ledger_totals = ledger.get("data", {}).get("totals", {})
    selected_agent = next(
        (a for a in agents.get("agents", []) if a.get("metrics", {}).get("budget_tokens") is not None),
        agents.get("agents", [None])[0],
    )

    proof_snapshot = {
        "fleet_cost_usd": agents.get("total_fleet_cost_usd", 0.0),
        "books_today_cost_usd": books_cost.get("today_cost_usd", 0.0),
        "books_today_tokens": books_cost.get("today_tokens", 0),
        "ledger_cost_usd": ledger_totals.get("cost_usd", 0.0),
        "ledger_tokens_total": ledger_totals.get("tokens_total", 0.0),
        "recent_accounting_events": len(recent_entries),
        "recent_notarized_events": len([e for e in recent_entries if e.get("verification") == "Notarized"]),
        "journal_chain_length": integrity.get("chain_length", 0),
        "demo_llm_total_calls": stats.get("total_calls", 0),
        "demo_llm_total_tokens": stats.get("total_tokens", 0),
        "demo_llm_total_cost_usd": stats.get("total_cost_usd", 0.0),
        "agent_budget_tokens": selected_agent.get("metrics", {}).get("budget_tokens", 0) if selected_agent else 0,
        "agent_budget_pct": selected_agent.get("metrics", {}).get("budget_pct", 0.0) if selected_agent else 0.0,
    }

    live_evidence = {
        "books_cost": books_cost,
        "ledger_totals": {
            "entry_count": ledger_totals.get("entry_count", 0),
            "tokens_total": ledger_totals.get("tokens_total", 0.0),
            "cost_usd": ledger_totals.get("cost_usd", 0.0),
            "tool_calls": ledger_totals.get("tool_calls", 0),
            "chain_verified": ledger.get("data", {}).get("chain_verified", False),
        },
        "agent_budget": {
            "agent": selected_agent.get("name") if selected_agent else None,
            "budget_tokens": selected_agent.get("metrics", {}).get("budget_tokens", 0) if selected_agent else 0,
            "budget_pct": selected_agent.get("metrics", {}).get("budget_pct", 0.0) if selected_agent else 0.0,
            "cost_usd": selected_agent.get("metrics", {}).get("cost_usd", 0.0) if selected_agent else 0.0,
        },
        "recent_accounting_sample": [
            {
                "seq_no": e.get("seq_no"),
                "action": e.get("action"),
                "outcome": e.get("outcome"),
                "account": e.get("debit", {}).get("account_label"),
                "verification": e.get("verification"),
            }
            for e in recent_entries[:3]
        ],
        "demo_llm_metering": stats,
        "service_source": service_kb.get("results", [])[:1],
    }

    prompt = f"""You are Connector's cost control copilot.

Using ONLY the live evidence below, write a 5-line operator summary.

Rules:
- Output exactly these labels and nothing else:
Status:
Spend:
Budget:
Value:
Next Step:
- Keep it operational, not essay-like.
- If spend is near zero, frame it as metering is live but runtime is currently low-cost.
- Emphasize budget visibility, token metering, and ledger-based attribution.

Proof snapshot:
{json.dumps(proof_snapshot, indent=2)}

Live evidence:
{json.dumps(live_evidence, indent=2)}
"""

    result = llm.generate(prompt, max_tokens=160)
    post_stats = llm.session_stats()

    proof_snapshot["current_slide_llm_tokens"] = result["meta"].get("total_tokens", 0)
    proof_snapshot["current_slide_llm_cost_usd"] = result["meta"].get("cost_usd", 0.0)
    proof_snapshot["session_total_calls_after_call"] = post_stats.get("total_calls", 0)
    live_evidence["demo_llm_metering"] = post_stats
    live_evidence["current_slide_llm_call"] = result["meta"]

    return {
        "slide": 8,
        "title": "Cost Control - Live Metering Posture",
        "service": "cost_control",
        "proof_snapshot": proof_snapshot,
        "live_evidence": live_evidence,
        "usable_capability_showcase": {
            "capability": "LLM-generated cost control summary from live metering and ledger evidence",
            "content": result["content"],
            "meta": result["meta"],
        },
        "verification": {
            "data_source": "Real Connector books, ledger, agent metrics, and LLM session metering",
            "read_only": True,
            "no_simulation": True,
            "llm_grounded_in_live_telemetry": True,
        },
        "cross_domain": ["customer_service", "legal_research", "financial_analysis"],
    }


def slide_9_audit_trail():
    """Slide 9: Audit Trail - Live Chain Proof"""

    journal = platform.get_books_journal(limit=10)
    books = platform.get_books_position()
    service_kb = platform.search_memory(
        "k/connector/service",
        "audit trail HMAC journal chain verification tamper-proof",
        top_k=1,
    )

    integrity = books.get("data", {}).get("integrity", {})
    entries = journal.get("entries", []) if isinstance(journal, dict) else []

    proof_snapshot = {
        "journal_entries_reviewed": len(entries),
        "chain_length": integrity.get("chain_length", 0),
        "chain_verified": integrity.get("chain_verified", False),
        "reconciliation_status": integrity.get("reconciliation_status", books.get("meta", {}).get("reconciliation_status", "UNKNOWN")),
        "trust_score": integrity.get("trust_score", 0),
        "recent_notarized_entries": len([e for e in entries if e.get("verification") == "Notarized"]),
    }

    live_evidence = {
        "journal_sample": [
            {
                "seq_no": e.get("seq_no"),
                "action": e.get("action"),
                "outcome": e.get("outcome"),
                "verification": e.get("verification"),
                "prev_hash": e.get("prev_hash"),
                "this_hash": e.get("this_hash"),
            }
            for e in entries[:3]
        ],
        "integrity": {
            "chain_length": integrity.get("chain_length", 0),
            "chain_verified": integrity.get("chain_verified", False),
            "trust_score": integrity.get("trust_score", 0),
            "trust_grade": integrity.get("trust_grade", "N/A"),
            "reconciliation_status": integrity.get("reconciliation_status", books.get("meta", {}).get("reconciliation_status", "UNKNOWN")),
        },
        "service_source": service_kb.get("results", [])[:1],
    }

    prompt = f"""You are Connector's audit copilot.

Using ONLY the live evidence below, write a 5-line operator summary.

Rules:
- Output exactly these labels and nothing else:
Status:
Chain:
Evidence:
Value:
Next Step:
- Keep it operational, not essay-like.
- Emphasize tamper-evidence, notarization, and reconciliation.

Proof snapshot:
{json.dumps(proof_snapshot, indent=2)}

Live evidence:
{json.dumps(live_evidence, indent=2)}
"""

    result = llm.generate(prompt, max_tokens=160)

    return {
        "slide": 9,
        "title": "Audit Trail - Live Chain Proof",
        "service": "audit_trail",
        "proof_snapshot": proof_snapshot,
        "live_evidence": live_evidence,
        "usable_capability_showcase": {
            "capability": "LLM-generated audit posture summary from live chain evidence",
            "content": result["content"],
            "meta": result["meta"],
        },
        "verification": {
            "data_source": "Real Connector books journal and integrity APIs",
            "read_only": True,
            "no_simulation": True,
            "llm_grounded_in_live_telemetry": True,
        },
        "cross_domain": ["financial_sox", "legal_custody", "gdpr"],
    }


def slide_10_compliance():
    """Slide 10: Compliance Reporting - Protected Evidence Posture"""

    books = platform.get_books_position()
    journal = platform.get_books_journal(limit=10)
    frameworks = platform.get_compliance_frameworks()
    service_kb = platform.search_memory(
        "k/connector/service",
        "compliance reporting HIPAA EU AI Act SOC2 regulatory",
        top_k=1,
    )

    integrity = books.get("data", {}).get("integrity", {})
    entries = journal.get("entries", []) if isinstance(journal, dict) else []
    frameworks_status = frameworks.get("status", 200 if "error" not in frameworks else None)

    proof_snapshot = {
        "trust_score": integrity.get("trust_score", 0),
        "trust_grade": integrity.get("trust_grade", "N/A"),
        "chain_verified": integrity.get("chain_verified", False),
        "reconciliation_status": integrity.get("reconciliation_status", books.get("meta", {}).get("reconciliation_status", "UNKNOWN")),
        "recent_notarized_entries": len([e for e in entries if e.get("verification") == "Notarized"]),
        "compliance_surface_status": frameworks_status,
    }

    live_evidence = {
        "compliance_signals": {
            "trust_score": integrity.get("trust_score", 0),
            "trust_grade": integrity.get("trust_grade", "N/A"),
            "tier": books.get("meta", {}).get("tier", "N/A"),
            "t0_chain_verified": books.get("meta", {}).get("t0_chain_verified", False),
            "reconciliation_status": integrity.get("reconciliation_status", books.get("meta", {}).get("reconciliation_status", "UNKNOWN")),
        },
        "journal_sample": [
            {
                "seq_no": e.get("seq_no"),
                "action": e.get("action"),
                "outcome": e.get("outcome"),
                "verification": e.get("verification"),
            }
            for e in entries[:3]
        ],
        "frameworks_surface": frameworks,
        "service_source": service_kb.get("results", [])[:1],
    }

    prompt = f"""You are Connector's compliance copilot.

Using ONLY the live evidence below, write a 5-line operator summary.

Rules:
- Output exactly these labels and nothing else:
Status:
Controls:
Access:
Value:
Next Step:
- Keep it operational, not essay-like.
- If the compliance endpoint is auth-protected, say the evidence surface is protected rather than broken.
- Emphasize mapped evidence, trust score, notarized trail, and role-gated reporting.

Proof snapshot:
{json.dumps(proof_snapshot, indent=2)}

Live evidence:
{json.dumps(live_evidence, indent=2)}
"""

    result = llm.generate(prompt, max_tokens=160)

    return {
        "slide": 10,
        "title": "Compliance Reporting - Protected Evidence Posture",
        "service": "compliance_reporting",
        "proof_snapshot": proof_snapshot,
        "live_evidence": live_evidence,
        "usable_capability_showcase": {
            "capability": "LLM-generated compliance posture summary from live trust and evidence signals",
            "content": result["content"],
            "meta": result["meta"],
        },
        "verification": {
            "data_source": "Real Connector books, journal, and compliance surface probe",
            "read_only": True,
            "no_simulation": True,
            "llm_grounded_in_live_telemetry": True,
        },
        "cross_domain": ["financial_sox", "legal_gdpr", "gov_fedramp"],
    }


SLIDES = {
    1: slide_1_infrastructure_positioning,
    2: slide_2_seven_services,
    3: slide_3_live_system_proof,
    4: slide_4_agent_isolation,
    5: slide_5_memory_dehallucination,
    6: slide_6_secure_tool_execution,
    7: slide_7_debugging_explainability,
    8: slide_8_cost_control,
    9: slide_9_audit_trail,
    10: slide_10_compliance,
}


def run_demo(start=1, end=10):
    """Run demo slides"""
    for n in range(start, end + 1):
        if n in SLIDES:
            try:
                result = SLIDES[n]()
                print(json.dumps(result, indent=2))
            except Exception as e:
                print(json.dumps({"error": str(e), "slide": n}))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_demo(1, 10)
    elif len(sys.argv) == 2:
        n = int(sys.argv[1])
        run_demo(n, n)
    else:
        run_demo(int(sys.argv[1]), int(sys.argv[2]))
