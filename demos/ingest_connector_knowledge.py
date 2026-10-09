#!/usr/bin/env python3
"""
Ingest Connector Infrastructure Knowledge
Populates k/connector/ namespace with detailed descriptions of the 7 services
"""

import requests
import json

BASE_URL = "http://localhost:9090"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer dev-token"
}

def register_agent():
    """Register knowledge ingestion agent"""
    payload = {
        "name": "connector_knowledge_ingest",
        "description": "Connector infrastructure knowledge ingestion",
        "clearance": 3
    }
    r = requests.post(f"{BASE_URL}/api/v1/agents", headers=HEADERS, json=payload)
    r.raise_for_status()
    return r.json()["pid"]

def write_knowledge(agent_pid, namespace, content, metadata=None):
    """Write knowledge packet to platform"""
    payload = {
        "agent_pid": agent_pid,
        "content": content,
        "namespace": namespace,
        "metadata": metadata or {}
    }
    r = requests.post(f"{BASE_URL}/api/v1/memory/write", headers=HEADERS, json=payload)
    r.raise_for_status()
    return r.json()

# Connector Infrastructure Knowledge Base
connector_knowledge = [
    {
        "ns": "k/connector/overview",
        "content": "Connector is the control plane for production AI agents. It provides kernel-level services for AI agents, just like an operating system provides services for processes. Connector sits beside your models, tools, and memory, providing 7 core infrastructure services: Agent Isolation, Memory Dehallucination, Secure Tool Execution, Debugging & Explainability, Cost Control, Audit Trail, and Compliance Reporting. Unlike generic AI infrastructure or LLM wrappers, Connector provides governed, auditable, compliant AI execution across any domain: healthcare, finance, legal, customer service.",
        "meta": {"category": "platform_overview", "version": "1.0"}
    },
    {
        "ns": "k/connector/service/agent_isolation",
        "content": "Agent Isolation: Multi-tenant agent execution with security boundaries. Component: Memory Kernel with MAC guard implementing Bell-LaPadula (confidentiality) and Biba (integrity) models. Each agent runs with a clearance level (L1, L2, L3). MAC enforces: no read-up (agent cannot read higher classification), no write-down (agent cannot write to lower classification without grant). Prevents data leakage between tenants. Use cases: Healthcare (patient data segregation by role), Finance (trading desk isolation), Legal (document access control), Customer Service (tier-based access).",
        "meta": {"service": "agent_isolation", "component": "memory_kernel", "security_model": "MAC"}
    },
    {
        "ns": "k/connector/service/memory_dehallucination",
        "content": "Memory Dehallucination: Grounded retrieval preventing LLM hallucination. Component: CID-addressed memory with BM25 semantic search. Every memory packet has a Content Identifier (CID) - a cryptographic hash proving provenance. BM25 algorithm (k1=1.5, b=0.75) ranks retrieved sources by relevance score. LLM must cite CID sources, preventing fabrication. Retrieval status labeled: RETRIEVED (grounded in KB) vs SIMULATED (LLM training data). Use cases: Healthcare (evidence-based clinical guidelines), Finance (regulatory compliance lookup), Legal (case law precedent search), Customer Service (policy Q&A).",
        "meta": {"service": "memory_dehallucination", "component": "memory_kernel", "algorithm": "BM25", "addressing": "CID"}
    },
    {
        "ns": "k/connector/service/secure_tool_execution",
        "content": "Secure Tool Execution: Governed tool calls with policy enforcement. Component: 5-layer guard pipeline. Layer 1 (MAC): Clearance-based access control. Layer 2 (Policy Engine): RBAC + ABAC combined, deny-overrides composition. Layer 3 (Content Guard): Prompt injection detection, PII scanning, jailbreak blocking. Layer 4 (Circuit Breaker): Rate limiting, anomaly detection, auto-isolation. Layer 5 (Audit + HITL): Every operation logged with HMAC, human-in-loop for high-risk ops. Generates signed execution receipts. Use cases: Healthcare (controlled substance prescribing), Finance (wire transfer approval), Legal (contract signing), Customer Service (refund authorization).",
        "meta": {"service": "secure_tool_execution", "component": "guard_pipeline", "layers": 5}
    },
    {
        "ns": "k/connector/service/debugging_explainability",
        "content": "Debugging & Explainability: Full cognitive trace and decision provenance. Component: 11-layer cognitive substrate. Layers: 1-Perception (input understanding), 2-Meaning (semantic interpretation), 3-Tension (problem identification), 4-Knowledge (KB retrieval), 5-Possibility (option generation), 6-Evaluation (ranking alternatives), 7-Expertise (domain reasoning), 8-Commitment (decision making), 9-Plan (action sequencing), 10-Exposure (risk assessment), 11-Reflection (meta-cognition). Every decision has traceable reasoning chain with source citations. Audit log shows full cognitive process. EU AI Act transparency compliant. Use cases: Healthcare (explainable diagnosis), Finance (credit underwriting trace), Legal (case analysis reasoning), Customer Service (escalation decisions).",
        "meta": {"service": "debugging_explainability", "component": "cognitive_substrate", "layers": 11, "compliance": "EU_AI_Act"}
    },
    {
        "ns": "k/connector/service/cost_control",
        "content": "Cost Control: Real-time token metering and budget enforcement. Component: Books ledger with token accounting. Tracks: LLM token costs (prompt + completion), memory write costs, agent operation costs. Budget enforcement: per-agent limits, circuit breaker triggers on overspend. Cost attribution: every operation has ledger entry with cost breakdown. ROI calculation: compare manual vs AI processing costs. Use cases: Healthcare (cost per clinical note), Finance (cost per analysis), Legal (cost per document review), Customer Service (cost per conversation).",
        "meta": {"service": "cost_control", "component": "books_ledger", "tracking": "real_time"}
    },
    {
        "ns": "k/connector/service/audit_trail",
        "content": "Audit Trail: Tamper-proof operation log with cryptographic verification. Component: HMAC-signed journal with chain verification. Every operation creates journal entry with: seq_no, timestamp, action, agent_pid, this_hash, prev_hash, HMAC signature. Chain verification: prev_hash of entry N+1 must match this_hash of entry N. Reconciliation status: RECONCILED means chain verified, no tampering. Notarized verification proves integrity. Supports regulatory audit (HIPAA, SOX, GDPR). Use cases: Healthcare (patient data access audit), Finance (transaction audit trail), Legal (chain of custody), Customer Service (interaction logging).",
        "meta": {"service": "audit_trail", "component": "books_journal", "verification": "HMAC", "tamper_proof": True}
    },
    {
        "ns": "k/connector/service/compliance_reporting",
        "content": "Compliance Reporting: Automated compliance verification for regulatory frameworks. Component: Compliance analyzer mapping system telemetry to controls. Frameworks: HIPAA (healthcare), EU AI Act (high-risk AI), SOC2 (security/availability/confidentiality). Evidence mapping: MAC guard → access control, HMAC journal → audit controls, CID addressing → integrity, HITL gates → human oversight. Trust score (0-100) computed from control satisfaction. Trust grade (A/B/C/D/F) for executive reporting. Generates certification-ready reports. Use cases: Healthcare (HIPAA compliance), Finance (SOX compliance), Legal (GDPR compliance), Government (FedRAMP compliance).",
        "meta": {"service": "compliance_reporting", "component": "compliance_analyzer", "frameworks": ["HIPAA", "EU_AI_Act", "SOC2"]}
    },
    {
        "ns": "k/connector/architecture/memory_kernel",
        "content": "Memory Kernel: Core runtime for memory operations. Implements: CID-addressed storage (content-addressable), bi-temporal indexing (valid-time + transaction-time), namespace isolation (k/ for knowledge, m/ for memory, etc.), MAC enforcement (Bell-LaPadula + Biba), syscall dispatch (agent → kernel → operation), packet management (create, read, update, seal), validation pipeline (schema, policy, guard), audit trail creation (every operation logged). Kernel ensures: data integrity (CID verification), access control (MAC + RBAC), provenance (full lineage), tamper-proof audit (HMAC chain).",
        "meta": {"component": "memory_kernel", "capabilities": ["CID_addressing", "MAC", "audit"]}
    },
    {
        "ns": "k/connector/architecture/guard_pipeline",
        "content": "Guard Pipeline: 5-layer security decision engine. Orchestrates security checks with early-exit on denial. Layer 1 (MAC): Bell-LaPadula confidentiality + Biba integrity. Layer 2 (Policy): RBAC (role-based) + ABAC (attribute-based), deny-overrides composition. Layer 3 (Content): Prompt injection patterns, PII detection (SSN, credit card, email), jailbreak attempt blocking, toxicity filtering. Layer 4 (Circuit Breaker): Rate limits (ops/minute), anomaly detection (statistical deviation), auto-isolation (suspicious behavior). Layer 5 (Audit + HITL): HMAC-signed verdict log, human-in-loop gates for high-risk operations, escalation workflows. Generates GuardVerdictChain for forensic analysis.",
        "meta": {"component": "guard_pipeline", "layers": 5, "early_exit": True}
    },
    {
        "ns": "k/connector/architecture/books",
        "content": "Books: Double-entry accounting ledger for AI operations. Implements: Journal (chronological log of all transactions), Ledger (account balances by category), Position (current system state snapshot). Accounts: 1110 (Active Memory), 3110 (Memory Deposits), cost tracking accounts. Every operation: debit + credit entries, HMAC signature, chain verification (prev_hash → this_hash). Reconciliation: verifies chain integrity, detects tampering, computes trust score. Supports: cost attribution, budget enforcement, compliance audit, forensic analysis. Tier system: T0 (kernel operations), T1 (agent operations), T2 (user operations).",
        "meta": {"component": "books", "accounting": "double_entry", "verification": "HMAC_chain"}
    },
    {
        "ns": "k/connector/architecture/cognitive_substrate",
        "content": "Cognitive Substrate: 11-layer thought process for explainable AI. Orchestrates agent reasoning through: 1-Perception (parse input), 2-Meaning (semantic understanding), 3-Tension (identify problem), 4-Knowledge (retrieve from KB with CID citations), 5-Possibility (generate options), 6-Evaluation (rank by criteria), 7-Expertise (apply domain heuristics), 8-Commitment (make decision), 9-Plan (sequence actions), 10-Exposure (assess risks), 11-Reflection (meta-reasoning). Each layer: produces artifacts, cites sources, logs to audit trail. Enables: full reasoning trace, source attribution, decision provenance, regulatory transparency (EU AI Act Article 13).",
        "meta": {"component": "cognitive_substrate", "layers": 11, "explainability": True, "compliance": "EU_AI_Act_Article_13"}
    },
    {
        "ns": "k/connector/cross_domain/healthcare",
        "content": "Connector in Healthcare: Agent Isolation (patient data by role), Memory Dehallucination (evidence-based clinical guidelines with citations), Secure Tool Execution (controlled substance prescribing with DEA checks), Debugging (explainable diagnosis reasoning), Cost Control (cost per SOAP note), Audit Trail (HIPAA-compliant patient access log), Compliance (automated HIPAA evidence mapping). Use cases: clinical documentation, prior authorization, differential diagnosis, medication reconciliation, clinical trial matching, radiology reporting.",
        "meta": {"domain": "healthcare", "compliance": "HIPAA", "use_cases": 7}
    },
    {
        "ns": "k/connector/cross_domain/finance",
        "content": "Connector in Finance: Agent Isolation (trading desk segregation), Memory Dehallucination (regulatory compliance lookup with CFR citations), Secure Tool Execution (wire transfer approval workflows), Debugging (credit decision trace), Cost Control (cost per analysis), Audit Trail (SOX-compliant transaction log), Compliance (automated SOX evidence mapping). Use cases: credit underwriting, fraud detection, regulatory reporting, risk analysis, portfolio management.",
        "meta": {"domain": "finance", "compliance": "SOX", "use_cases": 5}
    },
    {
        "ns": "k/connector/cross_domain/legal",
        "content": "Connector in Legal: Agent Isolation (document access by clearance), Memory Dehallucination (case law precedent search with citations), Secure Tool Execution (contract signing approval), Debugging (legal argument reasoning trace), Cost Control (cost per document review), Audit Trail (chain of custody for evidence), Compliance (GDPR-compliant data handling). Use cases: legal research, contract analysis, discovery, due diligence, compliance review.",
        "meta": {"domain": "legal", "compliance": "GDPR", "use_cases": 5}
    },
    {
        "ns": "k/connector/cross_domain/customer_service",
        "content": "Connector in Customer Service: Agent Isolation (tier-based access to customer data), Memory Dehallucination (policy Q&A with source citations), Secure Tool Execution (refund authorization workflows), Debugging (escalation decision trace), Cost Control (cost per conversation), Audit Trail (interaction logging for quality), Compliance (data privacy compliance). Use cases: chatbot automation, ticket routing, knowledge base Q&A, escalation management, sentiment analysis.",
        "meta": {"domain": "customer_service", "compliance": "data_privacy", "use_cases": 5}
    }
]

print("Ingesting Connector infrastructure knowledge...")
print(f"Target: {BASE_URL}")
print()

# Register agent
print("Registering knowledge ingestion agent...")
try:
    agent_pid = register_agent()
    print(f"✓ Agent registered: {agent_pid}")
except Exception as e:
    print(f"✗ Failed to register agent: {e}")
    print("Attempting to use existing agent...")
    r = requests.get(f"{BASE_URL}/api/v1/agents", headers=HEADERS)
    agents = r.json().get("agents", [])
    if agents:
        agent_pid = agents[0]["pid"]
        print(f"✓ Using existing agent: {agent_pid}")
    else:
        print("✗ No agents available. Exiting.")
        exit(1)

print()
total_ingested = 0

for item in connector_knowledge:
    try:
        result = write_knowledge(agent_pid, item["ns"], item["content"], item["meta"])
        if result.get("ok"):
            print(f"  ✓ {item['ns']} → CID: {result.get('cid', 'N/A')}")
            total_ingested += 1
        else:
            print(f"  ✗ {item['ns']}: {result}")
    except Exception as e:
        print(f"  ✗ {item['ns']}: {e}")

print()
print(f"Total ingested: {total_ingested} knowledge packets")
print("Connector infrastructure knowledge base ready for retrieval.")
