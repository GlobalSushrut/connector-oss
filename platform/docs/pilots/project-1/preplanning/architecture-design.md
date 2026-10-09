# Travel Governance Pilot — Architecture Design Document

## Executive Summary

This document defines the architecture for a **production-grade AI governance sidecar** for enterprise travel companies. The design maps industry-standard patterns (OpenTelemetry observability, Envoy-style sidecar proxy, policy guardrails) to Connector's actual capabilities (Admission Gate, SOE Surface Engine, tamper-evident audit chains).

**Key Design Decision**: Connector operates as a **control plane sidecar**—deployed alongside existing travel AI systems (search, booking, CRM)—capturing, governing, and auditing AI interactions without requiring application rewrites.

---

## 1. Industry Context & Standards Research

### 1.1 Sidecar Pattern (Production Standard)

**Industry Standard**: Microsoft Azure, AWS, and Kubernetes ecosystems use the sidecar pattern extensively:
- **Envoy Proxy**: Sidecar for service mesh traffic management
- **Dapr**: Sidecar for distributed application runtime
- **Open Service Mesh**: Uses MutatingAdmissionWebhook for automatic sidecar injection

**Why Sidecar for AI Governance**:
- **Non-intrusive**: Travel apps don't need code changes
- **Language-agnostic**: Works with Python (ML), Node.js (booking), Java (CRM)
- **Co-located**: Same pod/host → low latency (<5ms overhead)
- **Independent lifecycle**: Update governance without touching production apps

### 1.2 Observability Stack (Industry Standard)

**OpenTelemetry + Grafana/Loki/Tempo** is the emerging standard for AI agent observability:

| Component | Industry Standard | Connector Equivalent |
|-----------|------------------|----------------------|
| Metrics | Prometheus | SurfaceMetrics + internal metrics |
| Logs | Loki/CloudWatch | EngineAuditEntry (structured) |
| Traces | Jaeger/Tempo | ExecutionReceipt chains |
| Dashboard | Grafana | SOE Surface Engine + webhook feeds |

**Reference**: OpenTelemetry blog (2025) defines AI agent observability standards: spans for LLM calls, attributes for model/token counts, events for decisions.

### 1.3 Policy Guardrails (Industry Standard)

**Amazon Bedrock Guardrails**, **Guardrails AI**, and **Obsidian Security** establish patterns:
- **Runtime enforcement**: Policies evaluated per-request, not batch
- **Multi-layer**: MAC (Mandatory Access Control) → Content filtering → Circuit breaker
- **Deny-by-default**: Fail closed on policy engine failure
- **Audit everything**: Pass and deny both logged with tamper evidence

---

## 2. Connector Capability Mapping

### 2.1 What Connector Provides (Verified Capabilities)

#### **A. Admission Gate** (`platform/server/src/services/admission.rs`)
- **Central enforcement point** for ALL agent actions (LLM, memory, tools)
- **5-layer guard pipeline**: MAC → Policy → Content → CircuitBreaker → Audit+HITL
- **Quarantine capability**: Auto-pause agent on security violation + human-in-the-loop
- **< 200µs overhead**: Negligible vs LLM latency
- **Deny-by-default**: Returns `Err` → action MUST NOT execute

```rust
// Every execution path calls this
pub fn check(state: &SharedState, req: &AdmissionRequest) -> Result<AdmissionTicket, ConnectorError>
```

#### **B. Surface Output Engine (SOE)** (`oss/connector/crates/connector-engine/src/surface/engine.rs`)
- **Unified orchestrator** for all rendered output
- **CID-based content addressing**: `soe1-sha256-*` format for tamper evidence
- **Receipt/proof chains**: Every render produces signed `SurfaceReceipt`
- **Trust tiers**: T0 (Kernel) → T1 (Engine) → T2 (Derived) → T3 (Rendered)
- **Governance integration**: Role-based access, redaction, policy decisions
- **Time-travel queries**: `--at`, `--since`, `--last` selectors for replay

```rust
pub struct SurfaceEngine {
    cache: SurfaceCache,
    receipts: ReceiptChain,      // ← Tamper-evident audit chain
    governance: SurfaceGovernance,
    bus: SurfaceBus,             // ← Real-time event streaming
    kernel: KernelBridge,        // ← T0/T1 data source
    ...
}
```

#### **C. Memory Kernel with Audit Trail** (`oss/vac/crates/vac-core/src/kernel.rs`)
- **Tamper-evident storage**: Every memory operation CID-addressed
- **Execution receipts**: Chain of custody for all AI actions
- **Structured namespaces**: `/m/` (Memory), `/k/` (Knowledge), `/a/` (Agent), etc.

#### **D. Policy Engine** (`connector_engine::guard_pipeline`)
- **MAC layer**: Mandatory access control by namespace security level
- **Policy rules**: YAML-defined, hot-reloadable
- **Content inspection**: Semantic injection detection
- **Circuit breakers**: Per-agent failure rate limiting
- **HITL integration**: Human review queue for edge cases

### 2.2 Gap Analysis: What's Missing vs Industry

| Industry Need | Connector Status | Gap |
|--------------|------------------|-----|
| OpenTelemetry protocol | Partial | Need OTLP exporter for traces/metrics |
| Grafana dashboards | Missing | Need webhook + pre-built dashboards |
| Real-time alerting | Partial | Need webhook → PagerDuty/Slack |
| Travel-specific policies | Missing | Need travel domain policy pack |
| Consent UI | Missing | Need embeddable consent widget |

**Assessment**: Core governance engine is production-ready. Gaps are in **observability integrations** and **travel domain specifics**—both achievable within POC scope.

---

## 3. Architecture Overview

### 3.1 High-Level Stack (Your Layer Model)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  LAYER 5: VISUALIZATION & DASHBOARD (Industry: Grafana/Loki/Kibana)       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                         │
│  │  Grafana    │  │  Policy     │  │  Consent    │  ← Webhook-fed real-time│
│  │  Dashboard  │  │  Dashboard  │  │  Dashboard  │                         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                         │
│         │                │                │                                  │
│         ▼                ▼                ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  WEBHOOK DISPATCHER (SurfaceBus events → external systems)           │   │
│  │  • Audit events → Grafana/Loki                                      │   │
│  │  • Policy violations → Slack/PagerDuty                              │   │
│  │  • Consent changes → CRM webhook                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 4: CONTROL PLANE (Connector OS / "Top Controller")                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CONNECTOR PLATFORM (Rust)                                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │   │
│  │  │  Admission  │  │   Surface   │  │   Policy    │  │  Memory    │ │   │
│  │  │    Gate     │  │   Engine    │  │   Engine    │  │   Kernel   │ │   │
│  │  │  (enforcer) │  │  (renderer) │  │  (rules)    │  │  (storage) │ │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │   │
│  │         │                │                │               │        │   │
│  │         └────────────────┴────────────────┴───────────────┘        │   │
│  │                              │                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐│   │
│  │  │  SOE SURFACE CONTRACTS (Standardized output packages)            ││   │
│  │  │  • AgentSurface • AuditSurface • PolicySurface • ConsentSurface ││   │
│  │  └─────────────────────────────────────────────────────────────────┘│   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 3: DATA GUARDRAILS (Policy Enforcement Layer)                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  GUARD PIPELINE (5 layers - runs on every request)                   │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────┐ │   │
│  │  │  MAC     │→│  Policy  │→│   Content    │→│   Circuit    │→│Audit │ │   │
│  │  │  Layer   │ │  Rules   │ │   Filter     │ │   Breaker    │ │+HITL│ │   │
│  │  └──────────┘ └──────────┘ └──────────────┘ └──────────────┘ └──────┘ │   │
│  │                                                                       │   │
│  │  TRAVEL-SPECIFIC GUARDRAILS (YAML-defined):                          │   │
│  │  • consent_required: [marketing, personalization, data_retention]   │   │
│  │  • booking_threshold: 5000.00  # USD → requires_human_approval      │   │
│  │  • pii_detection: [passport, credit_card, dob] → redact_before_ai   │   │
│  │  • geographic_restriction: [GDPR, CCPA] → region-specific_policy    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 2: DATABASE & STORAGE (Outcome Persistence)                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STORAGE LAYER                                                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│  │  │  Memory      │  │  Knowledge   │  │  Audit       │             │   │
│  │  │  (redb)      │  │  (validated) │  │  (append-only│             │   │
│  │  │  /m/...      │  │  /k/...      │  │  chain)      │             │   │
│  │  │  • Traveler  │  │  • Trip      │  │  • CID addr   │             │   │
│  │  │    profiles  │  │    details   │  │  • Signed     │             │   │
│  │  │  • Consent   │  │  • Policy    │  │  • Replayable │             │   │
│  │  │    state     │  │    cache     │  │               │             │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │   │
│  │                                                                       │   │
│  │  MEMORY COMPILATION (Raw events → Structured state):               │   │
│  │  search_events → kafka_stream → policy_enforcement →                 │   │
│  │  knowledge_validation → memory_commit → profile_md + trip_md         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 1: SIDECAR INGRESS / INTEGRATION (Data Ingestion)                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  SIDECAR PROXY (Language-agnostic capture)                         │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │   │
│  │  │ Python SDK  │  │ Node.js SDK │  │  REST API   │  │  WebSocket │ │   │
│  │  │  (pip)      │  │   (npm)     │  │  (any lang) │  │  (streaming│ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │   │
│  │                                                                       │   │
│  │  CAPTURE POINTS (travel app integration):                            │   │
│  │  • AI search query → prompt + context + ranking output               │   │
│  │  • Booking attempt → user intent + AI recommendation + result      │   │
│  │  • CRM interaction → customer data + AI suggestion + override      │   │
│  │  • User feedback → explicit consent change + timestamp             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. POC Architecture (MVP Deliverable)

### 4.1 POC Scope (8 Weeks)

**Goal**: Prove Connector can capture, govern, and compile travel AI events into structured memory.

**Components**:

| Component | Tech | Deliverable |
|-----------|------|-------------|
| Event Capture | Python SDK + Kafka | Mock travel app streaming search/booking events |
| Policy Engine | Connector GuardPipeline | 3 live policies: consent check, booking threshold, PII redaction |
| Audit Storage | redb + CID | Tamper-evident log of all AI decisions |
| Memory Compiler | Surface Engine | `traveler_profile.md` + `trip_details.md` generation |
| Dashboard | Webhook → Grafana | Real-time policy dashboard (read-only) |
| AWS Deployment | ECS Fargate + Terraform | Sidecar deployed in client's AWS account |

### 4.2 POC Data Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│  MOCK TRAVEL APP (Python Flask)                                      │
│  • /search?destination=hawaii&budget=2000                            │
│  • /book?trip_id=abc&user_id=xyz                                   │
└──────────────────────┬───────────────────────────────────────────────┘
                       │ 1. SDK capture
                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CONNECTOR SIDECAR (ECS Fargate)                                     │
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │   CAPTURE   │───→│   ADMISSION │───→│   POLICY    │             │
│  │   SERVICE   │    │    GATE     │    │   ENGINE    │             │
│  │  (HTTP 8080)│    │ (enforcement│    │ (3 rules)   │             │
│  └─────────────┘    └─────────────┘    └──────┬──────┘             │
│                                                 │                    │
│                       ┌─────────────────────────┘                    │
│                       │ DENY → block + audit                        │
│                       │ PASS → proceed                               │
│                       ▼                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │   MEMORY    │←───│   SURFACE   │←───│   KERNEL    │             │
│  │   STORAGE   │    │   ENGINE    │    │   (redb)    │             │
│  │  (redb)     │    │ (compiler)  │    │             │             │
│  └──────┬──────┘    └──────┬──────┘    └─────────────┘             │
│         │                   │                                        │
│         │                   └─→ traveler_profile.md (CID-addressed)  │
│         └───────────────────→ trip_details.md (tamper-evident)     │
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐                                │
│  │   WEBHOOK   │───→│   GRAFANA   │  (external, webhook-fed)       │
│  │  DISPATCHER │    │  DASHBOARD  │                                │
│  └─────────────┘    └─────────────┘                                │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.3 POC Technical Specifications

**Compute**: ECS Fargate (1 vCPU, 2GB RAM) — ~$50/month baseline

**Storage**: EBS gp3 20GB for redb + S3 for audit exports

**Networking**: 
- ALB (Application Load Balancer) for HTTP API
- VPC endpoints for AWS services
- Security groups: Inbound 8080 (app → sidecar), 9090 (metrics)

**Integration Points**:
```python
# Python SDK usage (travel app side)
from connector import TravelGovernanceClient

client = TravelGovernanceClient(
    sidecar_url="http://connector-sidecar:8080",
    api_key="travel-api-key"
)

# Capture AI search
result = client.capture_search(
    user_id="user-123",
    prompt="beach vacation under $2000",
    ai_output={"recommendations": [...]},
    context={"consent": "marketing_opt_in"}
)
# → Returns: {admission: "PASS", audit_cid: "soe1-sha256-...", policy_applied: [...]}
```

---

## 5. Production Architecture (Scale Target)

### 5.1 Production Scale Requirements

| Metric | POC | Production (Year 1) |
|--------|-----|---------------------|
| Events/sec | 10 | 1,000 |
| Travelers | 1,000 | 1M+ |
| Retention | 30 days | 7 years (compliance) |
| Regions | 1 (us-east-1) | 3 (US, EU, APAC) |
| Availability | 99.9% | 99.99% |

### 5.2 Production Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  MULTI-REGION CONNECTOR MESH                                                    │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │  GLOBAL CONTROL PLANE (us-east-1, primary)                                 │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │
│  │  │  License    │  │   Policy    │  │   Agent     │  │   Global    │     │ │
│  │  │  Server     │  │   Sync      │  │   Registry  │  │   Audit     │     │ │
│  │  │  (veup)     │  │   (CEDAR)   │  │   (CID)     │  │   Archive   │     │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                           │
│         ┌──────────────────────────┼──────────────────────────┐                 │
│         │                          │                          │                 │
│         ▼                          ▼                          ▼                 │
│  ┌──────────────┐          ┌──────────────┐          ┌──────────────┐        │
│  │  US REGION   │          │  EU REGION   │          │  APAC REGION │        │
│  │  (us-east-1) │          │  (eu-west-1) │          │  (ap-south-1)│        │
│  │  ┌──────────┐│          │  ┌──────────┐│          │  ┌──────────┐│        │
│  │  │ Connector││          │  │ Connector││          │  │ Connector││        │
│  │  │  Node    ││          │  │  Node    ││          │  │  Node    ││        │
│  │  │ (EKS)    ││          │  │ (EKS)    ││          │  │ (EKS)    ││        │
│  │  └────┬─────┘│          │  └────┬─────┘│          │  └────┬─────┘│        │
│  │       │      │          │       │      │          │       │      │        │
│  │  ┌────┴─────┐│          │  ┌────┴─────┐│          │  ┌────┴─────┐│        │
│  │  │Sidecars  ││          │  │Sidecars  ││          │  │Sidecars  ││        │
│  │  │(per-pod) ││          │  │(per-pod) ││          │  │(per-pod) ││        │
│  │  └──────────┘│          │  └──────────┘│          │  └──────────┘│        │
│  └──────────────┘          └──────────────┘          └──────────────┘        │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │  OBSERVABILITY STACK (per region + global)                               │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │
│  │  │  Prometheus │  │   Grafana   │  │    Loki     │  │    Tempo    │     │ │
│  │  │  (metrics)  │  │(dashboards) │  │   (logs)    │  │  (traces)   │     │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Production Components

| Component | Production Spec | Rationale |
|-----------|-----------------|-----------|
| Compute | EKS (3 AZs) | Auto-scaling, pod disruption budgets |
| Storage | redb (hot) + S3 Glacier (cold) | 7-year compliance retention |
| Messaging | MSK (Managed Kafka) | 1M events/sec, cross-AZ replication |
| Cache | ElastiCache Redis | Policy cache, consent state |
| Secrets | AWS Secrets Manager + KMS | Key rotation, audit logging |
| Networking | VPC Lattice | Service mesh, mTLS |

---

## 6. Workflows (Detailed)

### 6.1 Core Workflow: AI Search Governance

**Trigger**: User searches "beach vacation under $2000"

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│  USER   │ → │ TRAVEL  │ → │CONNECTOR│ → │   AI    │ → │ RESPONSE│
│ SEARCH  │   │   APP   │   │ SIDECAR │   │ MODEL   │   │ TO USER │
└────┬────┘   └────┬────┘   └────┬────┘   └─────────┘   └─────────┘
     │             │             │
     │             │ 1. SDK.capture_search()        │
     │             │────────────→│
     │             │             │ 2. Admission Gate
     │             │             │    • Quarantine check
     │             │             │    • Guard Pipeline (5 layers)
     │             │             │    • Injection detection
     │             │             │    • Policy evaluation
     │             │             │
     │             │             │ 3a. POLICY DENY → Block
     │             │             │     • Example: No consent
     │             │             │     → Return 403 + audit log
     │             │             │
     │             │             │ 3b. POLICY PASS → Proceed
     │             │←────────────│ Return admission ticket
     │             │             │
     │             │ 4. AI call (now governed)        │
     │             │───────────────────────────────→│
     │             │             │                  │
     │             │             │ 5. Capture output │
     │             │             │←─────────────────│
     │             │             │
     │             │             │ 6. Memory compilation
     │             │             │    • Store event (CID-addressed)
     │             │             │    • Update traveler_profile
     │             │             │    • Update trip_details
     │             │             │    • Sign receipt
     │             │             │
     │←────────────│ Return results │                │
     │             │              │                 │
```

### 6.2 Core Workflow: Booking with Human-in-the-Loop

**Trigger**: User attempts to book $8,000 luxury package

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│  USER   │ → │ TRAVEL  │ → │CONNECTOR│ → │ POLICY  │ → │  HUMAN  │
│  BOOK   │   │   APP   │   │ SIDECAR │   │ ENGINE  │   │ REVIEW  │
└────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
     │             │             │             │             │
     │             │ SDK.capture_booking()     │             │
     │             │────────────→│             │             │
     │             │             │ Guard Pipeline evaluates
     │             │             │ threshold: $8000 > $5000
     │             │             │ requires_human_approval = true
     │             │             │             │
     │             │             │────────────→│ Create HITL
     │             │             │             │────────────→│ Notify agent
     │             │             │             │             │
     │←────────────│"Pending approval"         │             │
     │             │             │             │             │
     │             │             │             │             │←── Agent reviews
     │             │             │             │             │    in dashboard
     │             │             │             │             │
     │             │             │             │←────────────│ Approve/Deny
     │             │             │             │             │
     │             │             │ Resume booking            │
     │             │──────────────────────────→│             │
     │             │             │             │             │
     │←────────────│ Confirmation              │             │
```

### 6.3 Core Workflow: Regulatory Replay

**Trigger**: Regulator asks "Why did AI recommend this package to user-123 on March 15?"

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│REGULATOR│ → │  OPS    │ → │CONNECTOR│ → │  SOE    │ → │  PROOF  │
│  QUERY  │   │  CLI    │   │ PLATFORM│   │ ENGINE  │   │ PACKAGE │
└────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
     │             │             │             │             │
     │  connectorctl│             │             │             │
     │  surface     │             │             │             │
     │  render      │             │             │             │
     │  --type agent│             │             │             │
     │  --id user-123│             │             │             │
     │  --at 2025-03-15│         │             │             │
     │─────────────→│             │             │             │
     │             │             │             │             │
     │             │             │────────────→│ Time-travel query
     │             │             │             │ (SurfaceTimeSelector)
     │             │             │             │
     │             │             │             │ Pull from:
     │             │             │             │ • T0: Memory kernel
     │             │             │             │ • T1: Knowledge base
     │             │             │             │ • T2: Audit chain
     │             │             │             │
     │             │             │             │ Build SurfaceDocument:
     │             │             │             │ • Agent state
     │             │             │             │ • Decisions made
     │             │             │             │ • Policies applied
     │             │             │             │ • Full context
     │             │             │             │
     │             │             │             │ Sign + CID
     │             │             │             │────────────→│
     │             │             │             │             │
     │             │             │             │ Export:
     │             │             │             │ • JSON (machine)
     │             │             │             │ • PDF (regulator)
     │             │             │             │ • Markdown (audit)
     │             │             │             │
     │             │←────────────│─────────────│─────────────│
     │             │ Proof package delivered  │             │
     │             │ (signed, tamper-evident) │             │
```

---

## 7. Integration API Design

### 7.1 Travel App → Connector Sidecar

```yaml
# POST /v1/travel/capture/search
# SDK wraps this for Python/Node

request:
  event_id: "evt_search_abc123"
  timestamp: "2025-04-14T10:30:00Z"
  traveler:
    traveler_id: "tvl_xyz789"
    consent_state:
      marketing: true
      personalization: true
      data_retention: "30_days"
  search_context:
    prompt: "beach vacation under $2000"
    filters:
      destination: ["hawaii", "caribbean"]
      budget_max: 2000
      dates:
        check_in: "2025-06-01"
        check_out: "2025-06-07"
  ai_interaction:
    model: "gpt-4"
    system_prompt: "You are a helpful travel assistant..."
    user_prompt: "Find me beach vacations under $2000 for June"
    raw_output: {...}  # Full LLM response
    rankings:
      - item_id: "pkg_001"
        rank: 1
        score: 0.95
        explanation: "Matches budget and beach preference"

response:
  admission:
    status: "PASS"  # or "DENY"
    ticket_id: "adm_a1b2c3d4"
    injection_score: 0.12
    audit_cid: "soe1-sha256-abc123..."
  policies_applied:
    - policy: "consent_marketing"
      result: "ALLOW"
    - policy: "booking_threshold"
      result: "SKIP"  # No booking yet
    - policy: "pii_detection"
      result: "CLEAN"
  memory_update:
    traveler_profile_cid: "soe1-sha256-def456..."
    trip_details_cid: null  # No active trip
```

### 7.2 Connector → External Dashboard (Webhook)

```json
{
  "event_type": "policy.evaluation",
  "timestamp": "2025-04-14T10:30:00.123Z",
  "connector_node_id": "conn-node-us-east-1a",
  "payload": {
    "event_id": "evt_search_abc123",
    "traveler_id": "tvl_xyz789",
    "policy": "consent_marketing",
    "decision": "ALLOW",
    "context": {
      "consent_state": {"marketing": true},
      "triggered_by": "search_capture"
    },
    "audit_cid": "soe1-sha256-abc123..."
  },
  "signature": "ed25519-sig-..."
}
```

---

## 8. Risk Mitigation & Production Considerations

### 8.1 Failure Modes

| Scenario | Behavior | Mitigation |
|----------|----------|------------|
| Sidecar unreachable | App continues (degraded governance) | Circuit breaker: cache last-known consent |
| Policy engine slow | Timeout → deny (fail closed) | 100ms SLA, async fallback policies |
| Audit storage full | Buffer + alert | S3 spillover, CloudWatch alarm |
| High event volume | Throttle + queue | Kafka backpressure, horizontal scaling |

### 8.2 Security Model

- **mTLS**: Sidecar ↔ App communication
- **KMS**: Key rotation for signing keys
- **IAM**: Least-privilege AWS roles
- **Audit**: All access logged, quarterly penetration tests

---

## 9. Implementation Roadmap

### Phase 1: POC (Weeks 1-4)
- [ ] Python SDK for event capture
- [ ] 3 travel policies (consent, threshold, PII)
- [ ] redb storage + CID addressing
- [ ] Basic Grafana dashboard (webhook)

### Phase 2: Hardening (Weeks 5-6)
- [ ] Terraform for AWS deployment
- [ ] Load testing (100 events/sec)
- [ ] Security review
- [ ] Documentation

### Phase 3: Demo & Deliver (Weeks 7-8)
- [ ] Replay demo (regulator query)
- [ ] Profile compilation demo
- [ ] Client presentation
- [ ] Production roadmap

---

## 10. Connector-Specific Value Props

### vs. Building Bespoke
- **Time**: 8 weeks vs. 6+ months
- **Risk**: Battle-tested admission gate vs. new code
- **Compliance**: Tamper-evident by design vs. bolt-on

### vs. Competitors (Fiddler, Truera, Arthur)
- **Deployment**: Sidecar (your AWS) vs. SaaS (their cloud)
- **Cost**: Flat OSS + support vs. per-request SaaS pricing
- **Extensibility**: Full source code vs. black box

---

*Document Version: 1.0*
*Last Updated: 2025-04-14*
*Author: Connector Architecture Team*
