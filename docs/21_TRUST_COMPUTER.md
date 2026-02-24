# Trust Computer

> 5-dimension trust score, grades, kernel-derived verification
> Source: `connector/crates/connector-engine/src/trust.rs`

---

## Purpose

The `TrustComputer` computes a **Verification Completeness Score** (0–100) from real kernel data — not self-reported configuration flags. Every dimension is derived from actual audit entries, CID integrity checks, and operational data.

---

## TrustScore

```rust
pub struct TrustScore {
    pub score:      u32,         // 0–100
    pub grade:      String,      // A+ | A | B | C | D | F
    pub proof_cid:  Option<Cid>, // CID of the score itself (verifiable)
    pub dimensions: TrustDimensions,
    pub computed_at: i64,
}

pub struct TrustDimensions {
    pub memory_integrity:        u32,  // 0–20
    pub audit_completeness:      u32,  // 0–20
    pub authorization_coverage:  u32,  // 0–20
    pub decision_provenance:     u32,  // 0–20
    pub operational_health:      u32,  // 0–20
    pub claim_validity:          Option<u32>,  // 0–20 (optional 6th dimension)
}
```

---

## 5 Dimensions

### 1. Memory Integrity (max 20)

**Source**: Ring 0 — CID re-hash verification

```
For each packet in kernel:
  recompute CID from content
  compare to stored CID
  
score = (packets_with_valid_cid / total_packets) * 20
```

A score of 20 means every stored packet's content matches its CID — no tampering detected.

---

### 2. Audit Completeness (max 20)

**Source**: Ring 1 — HMAC audit chain

```
Verify HMAC chain integrity (no gaps, no modifications)
Count successful operations vs total operations

score = (successful_ops / total_ops) * 20
       × chain_intact_multiplier (1.0 if intact, 0.5 if broken)
```

A score of 20 means every kernel operation succeeded and the audit chain is unbroken.

---

### 3. Authorization Coverage (max 20)

**Source**: Ring 2 — VAKYA token coverage

```
For each MemWrite/ToolDispatch/Action in audit log:
  check if audit_entry.vakya_id is set

score = (ops_with_vakya_id / total_write_ops) * 20
```

A score of 20 means every write operation was authorized with a VAKYA token.

---

### 4. Decision Provenance (max 20)

**Source**: Ring 3 — evidence CID coverage

```
For each Decision/Extraction packet:
  check if provenance.evidence_refs is non-empty

score = (decisions_with_evidence / total_decisions) * 20
```

A score of 20 means every decision has at least one evidence CID linking it to source data.

---

### 5. Operational Health (max 20)

**Source**: Application layer — agent lifecycle correctness

```
Checks:
  - Agent registered before first operation (not "system" PID)
  - No Denied operations in audit log (or Denied < 5%)
  - No Failed operations (or Failed < 2%)
  - Sessions properly opened and closed
  - No integrity check failures

score = weighted sum of above checks
```

---

### 6. Claim Validity (optional, max 20)

**Source**: `ClaimVerifier` results

```
For each Claim verified by ClaimVerifier:
  Confirmed → +1
  NeedsReview → +0.5
  Rejected → 0

score = (confirmed_claims / total_claims) * 20
```

When present, the total score can reach 120. The final score is capped at 100.

---

## Grade Table

| Score | Grade | Meaning |
|-------|-------|---------|
| 95–100 | A+ | Exceptional — military/bank grade |
| 85–94 | A | Strong — production ready |
| 70–84 | B | Good — minor gaps |
| 50–69 | C | Acceptable — notable gaps |
| 30–49 | D | Weak — significant issues |
| 0–29 | F | Failing — do not trust |

---

## TrustComputer API

```rust
pub struct TrustComputer;

impl TrustComputer {
    pub fn compute(
        kernel:    &MemoryKernel,
        agent_pid: Option<&str>,  // None = compute for all agents
    ) -> TrustScore

    pub fn compute_with_claims(
        kernel:    &MemoryKernel,
        agent_pid: Option<&str>,
        claims:    &[VerificationResult],
    ) -> TrustScore
}
```

---

## Proof CID

The `TrustScore` itself is serialized to DAG-CBOR and hashed to a CID:

```rust
let score = TrustComputer::compute(&kernel, Some("pid:000001"));
// score.proof_cid = Some(Cid("bafyrei..."))
// Anyone can recompute this CID from the same kernel state
// If the CID matches → the score wasn't fabricated
```

---

## Python SDK Usage

```python
# vac-ffi
result = agent.run("What are the patient's allergies?", "user:alice")
print(result.trust)        # 87
print(result.trust_grade)  # "A"

# Full score breakdown
snap = c.kernel_export(10)
# snap["stats"]["total_packets"], snap["stats"]["total_audit_entries"]
```

---

## Rust API Usage

```rust
// connector-api/src/observe.rs
let output = pipeline.run("message", "user:alice")?;
let trust = output.trust();
// trust.score = 87
// trust.grade = "A"
// trust.dimensions.memory_integrity = 20
// trust.dimensions.audit_completeness = 20
// trust.dimensions.authorization_coverage = 18
// trust.dimensions.decision_provenance = 15
// trust.dimensions.operational_health = 14

let badge = TrustBadge::from_score(&trust);
// badge.badge = "✅ Trust Score: 87/100 (A) — Verified by Connector"
```
