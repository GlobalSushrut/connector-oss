# Security Model

> SecurityConfig, signing, SCITT, classification, MFA, delegation
> Source: `connector/crates/connector-api/src/security.rs`, `connector-api/src/config.rs`

---

## Security Rings

```
Ring 0: Cryptographic Foundation
  SHA2-256 + CIDv1 (tamper detection)
  Ed25519 (signing + delegation)
  HMAC-SHA256 (audit chain integrity)
  SHA256-CTR (payload encryption)

Ring 1: Memory Kernel Enforcement
  Namespace isolation (default-deny cross-namespace reads)
  AccessGrant syscall (explicit cross-namespace permission)
  Sealed packets (immutable after sealing)
  Rate limiting per (agent_pid, operation)
  Audit log — every syscall logged, HMAC-chained

Ring 2: Action Authorization
  VAKYA token required for every action
  PolicyRule evaluation (Allow/Deny/RequireApproval)
  BudgetTracker (token + cost + action limits)
  DelegationChain with Ed25519 per hop
  FederatedPolicyEngine (federation Deny is absolute)

Ring 3: Runtime Protection
  AgentFirewall (non-bypassable, in DualDispatcher)
  InstructionPlane (default-deny typed schemas)
  BehaviorAnalyzer (sliding window anomaly detection)
  CheckpointManager (WAL + atomic flush)

Ring 4: Developer Surface
  SecurityConfig (signing, SCITT, classification, MFA)
  FirewallConfig (presets: default/strict/hipaa)
  BehaviorConfig (thresholds, window size)
  YAML 3-tier config (Tier 1 mandatory, Tier 3 optional-revoke)
```

---

## SecurityConfig

```rust
// connector-api/src/security.rs
pub struct SecurityConfig {
    pub signing:              Option<SigningAlgorithm>,  // None | Ed25519
    pub scitt:                bool,
    pub data_classification:  Option<String>,  // PHI | PII | confidential | internal | public
    pub jurisdiction:         Option<String>,  // US | EU | UK | CA | AU
    pub retention_days:       u64,
    pub key_rotation_days:    u64,
    pub audit_export:         Option<String>,  // json | csv | otel
    pub max_delegation_depth: u8,              // default: 3
    pub require_mfa:          bool,
    pub ip_allowlist:         Vec<String>,
}

pub enum SigningAlgorithm { Ed25519 }
```

---

## Ed25519 Packet Signing

When `signing: Ed25519` is set:

1. Every `MemPacket` is signed with the kernel's Ed25519 keypair before storage
2. `AuthorityPlane.signature` field is populated
3. On read, signature is verified — mismatch = tampered packet
4. Key rotation: new keypair generated every `key_rotation_days` days; old packets retain their original signatures

```yaml
connector:
  security:
    signing: true
    key_rotation_days: 90
```

---

## SCITT Receipt Anchoring

When `scitt: true`:

1. Every `MemWrite` operation triggers a SCITT receipt request
2. Receipt stored in `redb` `scitt` table
3. Receipt provides cross-organization proof that a packet existed at a specific time
4. `ScittExchange` in `aapi-federation` handles cross-org attestation

```yaml
connector:
  security:
    signing: true
    scitt: true
```

---

## Data Classification

| Level | Description | Enforcement |
|-------|-------------|-------------|
| `PHI` | Protected Health Information | HIPAA controls, PII detection, strict firewall |
| `PII` | Personally Identifiable Information | GDPR controls, PII detection |
| `confidential` | Business confidential | SOC2 controls |
| `internal` | Internal use only | Standard controls |
| `public` | Public data | Minimal controls |

Classification is propagated to:
- `DispatcherSecurity.data_classification` — firewall PII detection
- `ComplianceVerifier` — framework-specific controls
- `MemPacket.authority` — stored with every packet

---

## Jurisdiction

| Code | Region | Frameworks Activated |
|------|--------|---------------------|
| `US` | United States | HIPAA, SOC2, NIST AI RMF |
| `EU` | European Union | GDPR, EU AI Act |
| `UK` | United Kingdom | UK GDPR |
| `CA` | Canada | PIPEDA |
| `AU` | Australia | Privacy Act |

---

## MFA Gate

When `require_mfa: true`:

- All `RequireApproval` actions require MFA verification before execution
- Implemented via `ApprovalRequest` / `ApprovalResponse` events in the AAPI pipeline
- MFA token validated before `PolicyDecision { allowed: true }` is returned

---

## Delegation Depth

`max_delegation_depth` (default: 3) limits UCAN-compatible delegation chains:

```
Agent A → delegates to Agent B → delegates to Agent C → delegates to Agent D
depth=1          depth=2              depth=3              BLOCKED (depth=4)
```

`CrossCellCapabilityVerifier` enforces this across cells.

---

## IP Allowlist

```yaml
connector:
  security:
    ip_allowlist: [10.0.0.0/8, 192.168.1.100]
```

When non-empty, `connector-server` rejects requests from IPs not in the allowlist. Empty = allow all.

---

## Audit Export

```yaml
connector:
  security:
    audit_export: json   # json | csv | otel
```

| Format | Description |
|--------|-------------|
| `json` | `KernelOps.export_json()` — full kernel snapshot as JSON |
| `csv` | Audit entries as CSV (audit_id, timestamp, operation, outcome, agent_pid, target_cid) |
| `otel` | OTLP-compatible resource_spans for OpenTelemetry ingestion |

---

## Compliance Presets

```rust
// Convenience methods on PipelineBuilder
.hipaa("US", 2555)
// Sets: comply=["hipaa"], classification=PHI, jurisdiction=US, retention_days=2555, signing=true

.soc2()
// Sets: comply=["soc2"], classification=confidential

.gdpr(1825)
// Sets: comply=["gdpr"], classification=PII, jurisdiction=EU, retention_days=1825

.dod()
// Sets: comply=["dod"], classification=TOP_SECRET, jurisdiction=US,
//       signing=Ed25519, scitt=true, require_mfa=true, max_delegation_depth=1

.signed()
// Sets: signing=Ed25519, scitt=true
```

---

## Threat Model

**Connector detects**:
- Silent data tampering (CID mismatch)
- Unauthorized memory reads (namespace isolation + AccessGrant)
- Audit trail gaps (HMAC chain verification)
- Memory modification after sealing (sealed_cids HashSet)
- Delegation chain forgery (Ed25519 per-hop signatures)
- Prompt injection (Firewall injection signal)
- PII leakage (Firewall PII detection)
- Behavioral anomalies (BehaviorAnalyzer sliding window)
- Replication divergence (Merkle root comparison)

**Connector does not prevent**:
- OS-level compromise (physical access, kernel exploits)
- Side-channel attacks
- Compromise of the LLM provider's infrastructure

For OS-level threats, combine with a TEE (Trusted Execution Environment) or HSM.

---

## Security Levels

| Level | Config | Use Case |
|-------|--------|----------|
| 0 (default) | No security config | Development, testing |
| 1 | `signing: true` | Production baseline |
| 2 | + `scitt: true` | Regulated industries |
| 3 | + `data_classification: PHI` + `comply: [hipaa]` | Healthcare |
| 4 | + `firewall: preset: hipaa` | Healthcare strict |
| 5 | + `require_mfa: true` | Finance, legal |
| 6 | + `cluster` + `replication_factor: 3` | High availability |
| 7 | `.dod()` | Military, government |

Every level **adds** security — no level removes it.
