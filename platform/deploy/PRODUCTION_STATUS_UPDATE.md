# Production Readiness Status Update

**Date:** May 21, 2026  
**Status:** MAJOR PROGRESS - Both plugins significantly closer to production

---

## Executive Summary

| Component | Previous Status | Current Status | Change |
|-----------|----------------|----------------|--------|
| **TraceTramp** | ⚠️ 4 blockers | ⚠️ 1 blocker | Redis optional, admin UI, tenancy, cage validation added |
| **WitnessCtl** | ⚠️ 4 blockers | ⚠️ 1 blocker | Bundle files, custody node, verify binary, admin UI added |

---

## TraceTramp — Detailed Update

### ✅ Completed Since Last Review

#### 1. Redis Made Optional
```rust
// storage.rs
pub async fn init_redis_optional(redis_url: Option<&str>) 
    -> Result<Option<ConnectionManager>, AppError> {
    // Returns None if URL is None, "off", "disabled", or "none"
    // Falls back to PostgreSQL-only for approval queue
}
```
- Configuration: `TRACETRAMP_REDIS_URL` is now optional
- Doctor warnings instead of failures when Redis missing
- PostgreSQL handles approval queue when Redis disabled

#### 2. Web Admin Dashboard
```
/admin/dashboard → serve static HTML from admin-ui/dashboard.html
```
- Dark-themed operator dashboard
- Live stats via `/admin/stats` API
- Links to approvals, health endpoints
- Embedded in binary via `include_str!`

**File:** `admin-ui/dashboard.html` (1.9KB)

#### 3. Tenancy Isolation Hardening
**New file:** `src/tenancy.rs`
```rust
pub fn tenant_redis_config_key(tenant_id: &str) -> String
pub fn validate_tenant_id(tenant_id: &str) -> Result<(), AppError>
```
- Redis keys tenant-scoped: `tenant:config:{tenant_id}`
- Empty/unknown tenant rejection
- Unit tests for isolation

#### 4. Cage Route Validation
**New file:** `src/cage.rs`
```rust
pub fn validate_cage_sha_address(sha_address: &str) -> Result<(), AppError>
```
- Hex-only validation (prevents path injection)
- Length: 8-128 characters
- Unit tests for rejection of `../` paths

#### 5. Compile Status
```bash
$ cargo check --manifest-path plugins/tracetramp/Cargo.toml
# Exit: 0 (warnings only - unused imports)
```

---

### ⚠️ Remaining Blocker

| Issue | Severity | Notes |
|-------|----------|-------|
| **Cage route load testing** | HIGH | Code complete but no load test results at 1000 req/sec |

**Evidence needed:**
- k6 or similar load test report showing:
  - p50 latency < 50ms
  - p99 latency < 200ms
  - 0% errors at 1000 req/sec sustained
  - Memory stable under load

---

### 📋 Pre-Production Checklist (TraceTramp)

- [x] Redis optional (fallback to PostgreSQL)
- [x] Web admin dashboard (replaces removed TUI)
- [x] Tenancy isolation (Redis key scoping, validation)
- [x] Cage address validation (hex-only, path injection prevention)
- [x] Self-loop prevention (data plane port check)
- [ ] Load test report (1000 req/sec sustained)
- [ ] Circuit breaker tested (provider failover)
- [ ] Provider key vault integration (multi-tenant)
- [ ] SSO/OIDC admin auth
- [ ] Helm chart for Kubernetes

---

## WitnessCtl — Detailed Update

### ✅ Completed Since Last Review

#### 1. Portable `.witness` Bundle Files
**New file:** `src/bundle_file.rs`
```rust
pub fn bundle_paths(session_id: Uuid, timestamp: i64) 
    -> (PathBuf, PathBuf, PathBuf)  // .witness, .witnessctl, .witness.json
    
pub fn load_bundle_json(path: &Path) -> Result<Value, String>
pub fn write_bundle_artifacts(...)
```
- Format: `witnessctl.evidence_bundle.v1`
- Three files: primary `.witness`, legacy `.witnessctl`, metadata `.witness.json`
- Configurable directory via `WITNESSCTL_BUNDLE_DIR`
- Unit tests for load/save roundtrip

#### 2. Standalone Verification Binary
**New file:** `src/bin/witnessctl-verify.rs`
```bash
$ witnessctl-verify ./evidence.witness --hmac-secret <secret>
# OR
$ WITNESSCTL_HMAC_SECRET=... witnessctl-verify ./evidence.witness
```
- No database required
- No server required
- Pure offline verification of bundle integrity
- Exit code: 0 = pass, 1 = tamper detected, 2 = usage error

#### 3. Custody Node Network
**New files:**
- `src/custody_node.rs` - Types, quorum verification, proof signing
- `src/bin/witnessctl-node.rs` - Regional custody node binary

```rust
pub struct CustodyNode { node_id, public_key, endpoint, region }
pub struct CustodyProof { session_id, node_id, capture_hash, timestamp, signature }

pub fn verify_quorum(proofs: &[CustodyProof], required_quorum: usize, secret: &str) 
    -> QuorumReport
```

**Quorum states:**
- `QuorumMet` - Sufficient valid proofs, hash consistent
- `QuorumPartial` - Some proofs valid but not enough
- `QuorumBroken` - Hash mismatch or no valid proofs

**Custody node operation:**
```bash
$ WITNESSCTL_CUSTODY_NODE_SECRET=... \
  WITNESSCTL_CUSTODY_NODE_ID=eu-west-1 \
  WITNESSCTL_CUSTODY_NODE_PORT=7444 \
  witnessctl-node
```

Endpoints:
- `GET /health` - Node health
- `POST /api/v1/custody/replicate` - Receive replication requests

#### 4. Web Admin Dashboard
```
GET /admin/dashboard → serve static HTML
```
- Dark-themed operator dashboard
- Live health status
- API documentation
- Links to sessions, health endpoints

**File:** `admin-ui/dashboard.html` (1.3KB)

#### 5. Library Surface for Tools
**New file:** `src/lib.rs`
```rust
pub mod bundle_file;
pub mod custody_node;
pub mod receipt;
pub mod types;
```
- Enables `witnessctl-verify` binary to use core logic
- Supports future external tooling

#### 6. Compile Status
```bash
$ cargo check --manifest-path plugins/witnessctl/Cargo.toml
# Exit: 0 (warnings only - deprecated base64, unused imports)
```

---

### ⚠️ Remaining Blocker

| Issue | Severity | Notes |
|-------|----------|-------|
| **Production custody network test** | MEDIUM | Code complete but no multi-node quorum test in production-like setup |

**Evidence needed:**
- 3+ custody nodes running
- Session replication across nodes
- Quorum verification achieving 2/3 consensus
- Failover test (1 node down, still 2/3 quorum)

---

### 📋 Pre-Production Checklist (WitnessCtl)

- [x] `.witness` bundle file format
- [x] Standalone offline verification (`witnessctl-verify`)
- [x] Custody node implementation (`witnessctl-node`)
- [x] Quorum verification logic (2/3 consensus)
- [x] Replication worker (PostgreSQL queue → custody nodes)
- [x] Web admin dashboard
- [ ] Multi-node custody network tested (3+ nodes)
- [ ] SOC2 compliance export (auditor-ready PDF)
- [ ] PII review interface (redaction preview)
- [ ] Helm chart for Kubernetes

---

## Integration Testing Scenario

### Test: End-to-End AI Agent Governance

```bash
# 1. Start TraceTramp (PostgreSQL only, no Redis)
TRACETRAMP_REDIS_URL=off \
TRACETRAMP_DATABASE_URL=postgres://... \
  tracetramp start --foreground

# 2. Start WitnessCtl
WITNESSCTL_DATABASE_URL=postgres://... \
  witnessctl cage start

# 3. Configure custody nodes (3 regions)
WITNESSCTL_CUSTODY_NODE_SECRET=shared-secret \
WITNESSCTL_CUSTODY_NODE_ID=us-east-1 \
WITNESSCTL_CUSTODY_NODE_PORT=7444 \
  witnessctl-node

WITNESSCTL_CUSTODY_NODE_SECRET=shared-secret \
WITNESSCTL_CUSTODY_NODE_ID=eu-west-1 \
WITNESSCTL_CUSTODY_NODE_PORT=7445 \
  witnessctl-node

WITNESSCTL_CUSTODY_NODE_SECRET=shared-secret \
WITNESSCTL_CUSTODY_NODE_ID=ap-south-1 \
WITNESSCTL_CUSTODY_NODE_PORT=7446 \
  witnessctl-node

# 4. Configure app to use both
export OPENAI_BASE_URL="http://localhost:9741/cage/tenant-sha/v1"
export WITNESS_PROXY="http://localhost:7443/witness/default"

# 5. Run AI agent
python agent.py

# 6. Seal evidence
witnessctl session seal default --output ./evidence.witness

# 7. Verify offline
witnessctl-verify ./evidence.witness --hmac-secret $SECRET
# Expected: PASSED: chain_valid captures=247 receipts=247

# 8. Verify custody quorum
curl http://localhost:7443/api/v1/sessions/default/quorum
# Expected: { "result": "QuorumMet", "valid_proofs": 3, "distinct_nodes": 3 }
```

---

## Resource Requirements (Updated)

### Minimal Deployment (No Redis, Single Custody Node)

| Component | CPU | RAM | Storage |
|-----------|-----|-----|---------|
| PostgreSQL | 2 vCPU | 4GB | 50GB SSD |
| TraceTramp | 2 vCPU | 2GB | 10GB |
| WitnessCtl | 1 vCPU | 1GB | 20GB (evidence) |
| **Total** | **5 vCPU** | **7GB** | **80GB** |

### Production Deployment (With Custody Network)

| Component | CPU | RAM | Nodes |
|-----------|-----|-----|-------|
| PostgreSQL | 2 vCPU | 4GB | 2 (primary + replica) |
| TraceTramp | 2 vCPU | 2GB | 3 (HA) |
| WitnessCtl | 1 vCPU | 1GB | 2 (HA) |
| Custody nodes | 0.5 vCPU | 512MB | 3 (multi-region) |
| **Total** | **11.5 vCPU** | **12.5GB** | **10 nodes** |

---

## Next Steps to Production

### Immediate (This Week)

1. **Load Test TraceTramp Cage Route**
   ```bash
   # Using k6
   k6 run --vus 100 --duration 5m cage-load-test.js
   # Target: 1000 req/sec, p99 < 200ms, 0% errors
   ```

2. **Custody Network Integration Test**
   ```bash
   # Start 3 custody nodes
   # Create session
   # Verify replication and quorum
   # Kill 1 node, verify 2/3 quorum still works
   ```

### Short Term (Next 2 Weeks)

3. **Helm Charts**
   - PostgreSQL with persistence
   - TraceTramp with HPA (horizontal pod autoscaler)
   - WitnessCtl with evidence volume claims
   - Custody nodes as DaemonSet or Deployment

4. **Security Hardening**
   - Penetration test cage route
   - Verify tenancy isolation (no cross-tenant leaks)
   - Auth audit (JWT validation, admin tokens)

5. **SOC2 Compliance Export**
   - Complete control-to-evidence mapping
   - Auditor report generation
   - PDF export with tamper-proof metadata

---

## Summary

**Major achievements:**
- Both plugins now have web admin dashboards (TUI removal mitigated)
- TraceTramp no longer requires Redis (PostgreSQL-only deployments possible)
- WitnessCtl has portable `.witness` bundles and offline verification
- Custody node network implemented with quorum verification
- Both compile clean with only minor warnings

**Remaining before production:**
- Load testing (TraceTramp)
- Multi-node custody testing (WitnessCtl)
- Helm charts for Kubernetes
- Security audit

**Estimated time to production:** 1-2 weeks (assuming load tests pass)
