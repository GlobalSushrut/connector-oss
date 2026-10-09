# TraceTramp + WitnessCtl — Production Readiness Plan

> **Connector OS integration status:** [`docs/93-tracetramp-witnessctl-production.md`](../../docs/93-tracetramp-witnessctl-production.md) — Phase 1 probes via `make tt-wc-prod-smoke`.

## Current State Assessment

| Component | Code Status | Prod Ready | Blockers |
|-----------|-------------|------------|----------|
| **TraceTramp** | 41 source files, 79K lines | 🟡 Phase 1–4 | Redis optional, Helm chart, cage/load smokes; full k6 SLO TBD |
| **WitnessCtl** | 18 source modules, 37K lines | 🟡 Phase 1–4 | `.witness`, `witnessctl-verify`, custody + Helm chart |

---

## Part I: TraceTramp Production Plan

### Current Implementation Analysis

**What's Working:**
- Dual-plane architecture (data :9741, management :9742)
- CLI: `start`, `stop`, `status`, `doctor`, `setup`
- Provider implementations: OpenAI, Anthropic, Azure, Ollama stubs
- PostgreSQL migrations (12 migration files)
- Redis integration for rate limiting
- Control vs View pipeline separation
- Decision tree logging
- Policy enforcement hooks
- Budget tables + cost tracking

**Critical Gaps:**

| Gap | Severity | Impact |
|-----|----------|--------|
| TUI removed | HIGH | No visual dashboard for operators |
| Redis required | MEDIUM | Adds infrastructure complexity |
| Cage route load untested | CRITICAL | Core feature unverified under load |
| Provider key injection unclear | HIGH | Multi-tenant credential handling |
| HITL queue UI missing | MEDIUM | Approvals exist but no review interface |
| Decision tree storage partial | MEDIUM | Trees logged but query interface missing |

### Production Milestones

#### Phase 1: Foundation (Week 1-2)

**Goal:** Remove hard blockers, simplify deployment

**Tasks:**

1. **Make Redis Optional** (Week 1)
   ```rust
   // In config.rs
   pub struct Config {
       // Change from:
       pub redis_url: String,
       // To:
       pub redis_url: Option<String>,
       pub rate_limiter: RateLimiterType, // InMemory | Redis | Off
   }
   ```
   - Add `DashMap` or `scc::HashMap` in-memory rate limiter
   - Fall back when Redis unavailable
   - Update `doctor` to warn instead of fail on missing Redis

2. **Add Web Dashboard** (Week 1-2)
   Replace removed TUI with minimal web UI:
   ```
   GET /admin/dashboard → Serve static HTML
   
   Dashboard pages:
   - Live Traces (WebSocket stream)
   - Active Approvals (HITL queue)
   - Budget Burn (per tenant)
   - Decision Trees (searchable)
   ```
   
   Implementation:
   - Add `admin-ui/` folder with HTML/JS
   - Serve via Axum `tower_http::services::ServeDir`
   - Real-time via WebSocket on `/ws/traces`

3. **Provider Key Resolution** (Week 2)
   ```rust
   // Current: unclear how tenant gets provider key
   // Target: Vault integration
   pub async fn resolve_provider_key(
       &self,
       tenant_id: &str,
       provider: Provider,
   ) -> Result<ProviderKey> {
       // 1. Check tenant-specific vault entry
       // 2. Fall back to default if allowed
       // 3. Audit log access
   }
   ```
   
   Add to database:
   ```sql
   CREATE TABLE tenant_provider_keys (
       tenant_id TEXT,
       provider TEXT,
       key_reference TEXT, -- vault path, NOT actual key
       encrypted_key BYTEA, -- optional: direct encryption
       allowed_models TEXT[],
       budget_usd_monthly DECIMAL(12,2),
       created_at TIMESTAMPTZ
   );
   ```

**Deliverable:** `tracetramp start` works with just PostgreSQL, web dashboard accessible

---

#### Phase 2: Cage Hardening (Week 3-4)

**Goal:** Core cage route production-ready

**Tasks:**

1. **Cage Route Load Testing** (Week 3)
   ```bash
   # Using k6 or similar
   k6 run --vus 100 --duration 5m cage-load-test.js
   
   # Metrics:
   - p50 latency < 50ms
   - p99 latency < 200ms
   - 0% error rate at 1000 req/sec
   - Memory stable under 512MB
   ```
   
   Test scenarios:
   - OpenAI proxy (streaming + non-streaming)
   - Budget exhaustion edge case
   - Policy block response path
   - Connection pool exhaustion

2. **Self-Loop Prevention** (Week 3)
   Already partially implemented — verify and harden:
   ```rust
   // In gateway.rs — cage route handler
   async fn cage_proxy(
       State(state): State<AppState>,
       Path((tenant_sha, path)): Path<(String, String)>,
       req: Request<Body>,
   ) -> Result<Response<Body>> {
       // 1. Verify tenant_sha is valid (prevent enumeration)
       // 2. Check tenant quota before proxying
       // 3. Transform request (inject tracking headers)
       // 4. Stream response with tee for logging
       // 5. Post-process: decision tree, cost attribution
   }
   ```

3. **Circuit Breaker + Retry** (Week 4)
   ```rust
   pub struct ProviderCircuit {
       failures: AtomicU32,
       last_failure: AtomicInstant,
       state: AtomicState, // Closed | Open | HalfOpen
   }
   
   // On provider failure:
   // 1. Increment failure count
   // 2. If threshold exceeded → Open circuit
   // 3. Return 503 with fallback suggestion
   // 4. After timeout → HalfOpen (test request)
   ```

4. **Tenancy Isolation Audit** (Week 4)
   Verify in code review:
   - [ ] No cross-tenant cache leakage
   - [ ] No shared connection pools across tenants
   - [ ] Tenant ID validated on every request
   - [ ] Budget checks use correct tenant context

**Deliverable:** Load test report showing 1000 req/sec sustained, circuit breaker functional

---

#### Phase 3: Enterprise Features (Week 5-8)

**Goal:** SSO, audit, HITL, exports

**Tasks:**

1. **SSO Integration** (Week 5)
   ```rust
   // Admin API auth — currently JWT only
   // Add OAuth2/OIDC:
   pub enum AdminAuth {
       Jwt(JwtClaims),
       Oidc(OidcClaims),
       ApiKey(ApiKeyClaims),
   }
   ```
   
   Supported IdPs:
   - Okta
   - Auth0
   - Azure AD
   - Keycloak (self-hosted)

2. **HITL Approval UI** (Week 5-6)
   ```sql
   CREATE TABLE approval_requests (
       id UUID PRIMARY KEY,
       tenant_id TEXT,
       request_type TEXT, -- "high_cost" | "pii_detected" | "sensitive_tool"
       request_details JSONB,
       requested_by TEXT,
       approvers TEXT[],
       status TEXT, -- "pending" | "approved" | "rejected" | "expired"
       created_at TIMESTAMPTZ,
       expires_at TIMESTAMPTZ,
       resolved_at TIMESTAMPTZ,
       resolution_reason TEXT
   );
   ```
   
   Web UI:
   - Approval queue with filters
   - One-click approve/reject
   - Bulk actions
   - Slack/email notifications

3. **Decision Tree Export** (Week 6)
   ```bash
   GET /api/v1/decisions/:trace_id/export?format=json|pdf
   
   # PDF contains:
   - Request metadata
   - Policy verdicts (with rule names)
   - Budget verdicts
   - PII scan results
   - Final decision with human-readable reason
   ```

4. **Multi-Region Routing** (Week 7-8)
   ```yaml
   # tracetramp.yaml
   regions:
     us-east:
       provider: openai
       endpoint: https://api.openai.com
       priority: 1
     eu-west:
       provider: azure-openai
       endpoint: https://myresource.openai.azure.com
       priority: 2
       compliance: [gdpr]
   
   routing:
     strategy: latency  # latency | cost | compliance
     fallback: true
   ```

**Deliverable:** SSO login working, approval workflow e2e tested, GDPR-compliant EU routing

---

#### Phase 4: Packaging & Distribution (Week 9)

**Goal:** One-command install, Docker, K8s

**Tasks:**

1. **Release Tarball**
   ```bash
   tracetramp-0.2.0-linux-amd64.tar.gz
   ├── bin/tracetramp
   ├── bin/tracetramp-admin  # CLI for admin ops
   ├── share/admin-ui/       # Static web dashboard
   ├── share/migrations/     # SQL files
   └── config/tracetramp.yaml.example
   ```

2. **Docker Image**
   ```dockerfile
   # Multi-stage build
   FROM rust:1.75 as builder
   COPY . .
   RUN cargo build --release
   
   FROM debian:bookworm-slim
   COPY --from=builder /app/target/release/tracetramp /usr/local/bin/
   COPY --from=builder /app/admin-ui /usr/share/tracetramp/admin-ui/
   COPY --from=builder /app/migrations /usr/share/tracetramp/migrations/
   
   ENTRYPOINT ["tracetramp"]
   CMD ["serve"]
   ```

3. **Helm Chart**
   ```yaml
   # values.yaml
   replicaCount: 3
   
   postgresql:
     enabled: true
     auth:
       database: tracetramp
   
   redis:
     enabled: false  # Use in-memory by default
   
   ingress:
     enabled: true
     hosts:
       - host: tracetramp.mycompany.com
   ```

**Deliverable:** `helm install tracetramp connector/tracetramp` works

---

#### Phase 5: Certification (Week 10-12)

**Goal:** SOC 2, security audit, performance benchmark

**Tasks:**
- [ ] Penetration test (cage route, admin API, tenancy isolation)
- [ ] Load test to 10K req/sec
- [ ] Chaos engineering (provider failure, DB failover, network partition)
- [ ] SOC 2 Type II readiness review
- [ ] Security audit report

**Deliverable:** Public security whitepaper, SOC 2 report available

---

## Part II: WitnessCtl Production Plan

### Current Implementation Analysis

**What's Working:**
- Session management (`witnessctl session open/list/seal`)
- Proxy capture engine
- HMAC receipt chain
- Chain verification (`witnessctl verify`, `verify-bundle`)
- Compliance framework definitions (SOC2, ISO27001)
- Export engine (PDF, JSON, CSV, Markdown)
- Webhook worker
- Custody worker (placeholder)
- Cage mode with route filtering
- Database migrations (16 files)

**Critical Gaps:**

| Gap | Severity | Impact |
|-----|----------|--------|
| TUI removed | HIGH | No real-time session monitoring |
| Custody replicas placeholder | CRITICAL | Multi-witness quorum not implemented |
| `.witness` bundle file | HIGH | No portable evidence artifact |
| Compliance exports partial | MEDIUM | Control-to-evidence mapping incomplete |
| PII redaction preview | MEDIUM | Detection works, preview not in UI |
| No web dashboard | HIGH | Operators need visual interface |

### Production Milestones

#### Phase 1: Evidence Integrity (Week 1-2)

**Goal:** Portable, verifiable evidence bundles

**Tasks:**

1. **`.witness` Bundle Format** (Week 1)
   ```rust
   pub struct WitnessBundle {
       pub header: BundleHeader,
       pub captures: Vec<Capture>,
       pub receipts: Vec<Receipt>,
       pub custody_proofs: Vec<CustodyProof>,
       pub compliance_map: ComplianceMap,
   }
   
   pub struct BundleHeader {
       pub version: String,
       pub session_id: String,
       pub created_at: DateTime<Utc>,
       pub sealed_at: DateTime<Utc>,
       pub hmac_hash: String,
       pub chain_hash: String,
   }
   ```
   
   CLI:
   ```bash
   witnessctl seal <session_id> --output ./evidence.witness
   # Creates: evidence.witness (binary) + evidence.witness.json (metadata)
   
   witnessctl verify-bundle ./evidence.witness
   # Output: chain_valid: true, captures: 247, custody_quorum: 3/3
   ```

2. **Independent Verification** (Week 2)
   Create `witnessctl-verify` standalone binary:
   ```bash
   # No database needed, no server
   witnessctl-verify ./evidence.witness --hmac-secret <secret>
   
   # Should verify:
   # 1. Bundle integrity (HMAC)
   # 2. Receipt chain (each link hashes previous)
   # 3. Custody signatures (if present)
   # 4. Compliance mappings
   ```

**Deliverable:** `seal` produces `.witness` file, `verify-bundle` works offline

---

#### Phase 2: Custody Network (Week 3-5)

**Goal:** Multi-witness quorum for tamper-proof evidence

**Tasks:**

1. **Custody Node Implementation** (Week 3)
   ```rust
   pub struct CustodyNode {
       pub node_id: String,
       pub public_key: String,
       pub endpoint: String,
       pub region: String,
   }
   
   pub struct CustodyProof {
       pub session_id: String,
       pub node_id: String,
       pub capture_hash: String,
       pub timestamp: DateTime<Utc>,
       pub signature: String,
   }
   ```
   
   Node behavior:
   - Receive session metadata from primary WitnessCtl
   - Independently hash captures
   - Sign custody proofs
   - Store encrypted backup

2. **Quorum Logic** (Week 4)
   ```rust
   pub fn verify_quorum(
       proofs: &[CustodyProof],
       required_quorum: usize,
   ) -> QuorumResult {
       // 1. Validate each signature
       // 2. Check hash consistency across nodes
       // 3. Verify temporal ordering
       // 4. Return: QuorumMet | QuorumPartial | QuorumBroken
   }
   ```

3. **Custody Node Operator** (Week 5)
   ```bash
   # Run by partners or internal teams in different regions
   witnessctl-node --region eu-west --primary https://witnessctl.us-east.company.com
   
   # Joins as custody witness
   # Replicates sessions
   # Signs proofs
   # Provides geo-redundancy
   ```

**Deliverable:** 3 custody nodes replicating, quorum verification working

---

#### Phase 3: Web Dashboard (Week 6-7)

**Goal:** Replace removed TUI with web interface

**Tasks:**

1. **Dashboard Server** (Week 6)
   ```rust
   // In routes.rs
   .route("/dashboard", get(serve_dashboard))
   .route("/ws/live", get(live_websocket))
   
   // Dashboard pages:
   // - Live Sessions (real-time captures)
   // - Session History (searchable)
   // - Chain Verification (visual chain)
   // - Compliance Export (wizard)
   // - PII Review (redaction preview)
   ```

2. **Live Session View** (Week 6-7)
   WebSocket streaming:
   ```javascript
   // dashboard/live.js
   const ws = new WebSocket('wss://witnessctl.company.com/ws/live?session=wit-xxx');
   ws.onmessage = (event) => {
       const capture = JSON.parse(event.data);
       renderCapture(capture);
       updateChainStatus(capture.receipt_status);
   };
   ```
   
   UI components:
   - Capture list with filters
   - Request/response inspector
   - Receipt chain visualization
   - PII hit highlighting
   - Chain status badge: [CHAIN OK] | [BROKEN] | [PENDING]

3. **PII Review Interface** (Week 7)
   ```sql
   -- pii_hits table needs preview columns
   ALTER TABLE witness_pii_hits ADD COLUMN preview_original TEXT;
   ALTER TABLE witness_pii_hits ADD COLUMN preview_redacted TEXT;
   ```
   
   UI:
   - Side-by-side original/redacted
   - Field-level approval
   - Bulk redaction actions
   - Export with/without PII

**Deliverable:** Web dashboard functional, PII review working

---

#### Phase 4: Compliance Certification (Week 8-10)

**Goal:** Auditor-ready exports

**Tasks:**

1. **Control-to-Evidence Mapping** (Week 8)
   ```yaml
   # compliance_map.yaml
   soc2_cc6_1:
     description: "Logical and physical access controls"
     evidence_queries:
       - "SELECT * FROM witness_captures WHERE auth_method IS NOT NULL"
       - "SELECT * FROM witness_sessions WHERE locked = true"
     required_captures: 10
     
   soc2_cc6_6:
     description: "Security infrastructure and software"
     evidence_queries:
       - "SELECT * FROM witness_captures WHERE pii_detected = true AND redaction_applied = true"
     required_captures: 5
   ```

2. **Auditor Report Generation** (Week 9)
   ```bash
   witnessctl compliance-report --framework soc2 --period Q1-2024 --output soc2-evidence.pdf
   
   # PDF contains:
   # - Executive summary
   # - Control coverage matrix
   # - Sample captures with chain verification
   # - Custody quorum status
   # - PII handling attestation
   ```

3. **Continuous Compliance** (Week 10)
   - Scheduled exports (daily/weekly)
   - Integration with GRC platforms (Vanta, Drata, Secureframe)
   - Evidence retention policies
   - Auto-archive after retention period

**Deliverable:** SOC 2 evidence export passes auditor review

---

#### Phase 5: Packaging & Distribution (Week 11)

**Goal:** Same as TraceTramp — Docker, Helm, one-command install

**Tasks:**
1. Release tarball with `witnessctl` + `witnessctl-node` + `witnessctl-verify`
2. Docker image with embedded web dashboard
3. Helm chart with PostgreSQL + custody node sidecars
4. Documentation site

**Deliverable:** `helm install witnessctl connector/witnessctl` works

---

## Part III: Integration & Testing

### End-to-End Test Scenarios

#### Scenario 1: AI Agent Traffic Governance

```bash
# 1. Start TraceTramp
tracetramp start --foreground

# 2. Start WitnessCtl (captures evidence)
witnessctl cage start

# 3. Configure app to use both
export OPENAI_BASE_URL="http://localhost:9741/cage/mytenant/v1"
export WITNESS_PROXY="http://localhost:7443/witness/default"

# 4. Run AI agent
python agent.py

# 5. Observe:
# - TraceTramp: decision trees, budget tracking
# - WitnessCtl: captures with receipts

# 6. Generate compliance report
witnessctl compliance-report --session default --framework soc2
```

#### Scenario 2: Incident Investigation

```bash
# Security incident detected
# Need to prove what happened

# 1. Locate session
witnessctl session list
# → Found: session=incident-2024-01-15

# 2. Verify chain
witnessctl verify incident-2024-01-15
# → Chain valid: 247 captures, 0 tampering

# 3. Export evidence bundle
witnessctl seal incident-2024-01-15 --output incident.witness

# 4. Hand to auditor
witnessctl-verify incident.witness --hmac-secret $SECRET
# → Independent verification: PASSED
```

---

## Part IV: Success Criteria

### TraceTramp Launch Criteria

| Criterion | Target | Verification |
|-----------|--------|--------------|
| Cage route latency | p99 < 200ms | k6 load test |
| Throughput | 1000 req/sec sustained | k6 load test |
| Error rate | < 0.1% | 7-day production burn-in |
| Tenancy isolation | 0 cross-tenant leaks | Penetration test |
| Provider failover | < 5s detection | Chaos test |
| Dashboard uptime | 99.9% | Monitoring |

### WitnessCtl Launch Criteria

| Criterion | Target | Verification |
|-----------|--------|--------------|
| Bundle verification | 100% offline | Unit tests |
| Custody quorum | 3 nodes, 2/3 quorum | Integration test |
| Chain integrity | 0 tampering undetected | Security audit |
| SOC 2 export | Auditor approved | Pilot with customer |
| Dashboard response | < 1s page load | Lighthouse |

---

## Timeline Summary

| Week | TraceTramp | WitnessCtl |
|------|------------|------------|
| 1-2 | Redis optional, web dashboard, provider keys | `.witness` bundles, offline verification |
| 3-4 | Cage load testing, circuit breaker, tenancy audit | Custody node implementation |
| 5-6 | SSO integration | Custody quorum logic |
| 7-8 | HITL approval UI, multi-region routing | Web dashboard, PII review |
| 9-10 | Decision exports, packaging | Compliance mapping, auditor reports |
| 11 | Docker, Helm charts | Docker, Helm charts |
| 12 | Security certification, pen test | Continuous compliance, GRC integration |

**Target Launch:** Week 12 for both products

---

## Resource Requirements

### Engineering
- 2 senior Rust engineers (full-time, weeks 1-12)
- 1 frontend engineer (weeks 1-2, 5-8 for dashboards)
- 1 DevOps engineer (weeks 9-11 for packaging)
- 1 security engineer (week 12 for certification)

### Infrastructure
- PostgreSQL: 2 vCPU, 4GB RAM per instance
- TraceTramp: 2 vCPU, 2GB RAM per replica
- WitnessCtl: 1 vCPU, 1GB RAM per replica
- WitnessCtl custody nodes: 3x (1 vCPU, 512MB each)
- Redis (optional): 1 vCPU, 1GB

### External
- Penetration testing vendor: $15K
- SOC 2 auditor: $25K
- Load testing infrastructure: $2K

---

*This plan assumes full-time focus on these two products. Adjust timeline if resources shared with other initiatives.*
