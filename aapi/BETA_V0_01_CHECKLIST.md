# AAPI Beta v0.01 Readiness Checklist

This checklist is a **truthful gap analysis**: what’s missing from the current repo to be considered **Beta v0.01**.

**Definition of Beta v0.01 for AAPI**
- API surface is still evolving, but core flows are stable enough for external contributors/users.
- The project has a documented security posture and safe defaults.
- CI is in place and contributors can run tests locally.
- The Gateway enforces policy/auth boundaries (not just "logs everything").

---

## 0) Baseline (already working)
- VĀKYA schema and canonicalization
- Gateway HTTP API with IndexDB logging
- Merkle transparency proofs
- File + HTTP adapters (effects captured)
- Python SDK with examples

---

## 1) Security Boundary (AuthN/AuthZ) — **Required for Beta**
### 1.1 Mandatory security modes
- [ ] **Dev mode**: allow unsigned calls for local experimentation.
- [ ] **Prod mode**: reject unsigned VĀKYA submissions.
- [ ] Config flag (env + config) that sets this explicitly.

### 1.2 Signature verification enforcement
- [ ] Gateway must verify signatures when `verify_signatures=true`.
- [ ] Gateway must define what happens when `signature` or `key_id` is missing.
- [ ] Key management story: how clients register public keys.
- [ ] Receipt signing/verification (optional but recommended for Beta).

### 1.3 Capability verification enforcement
- [ ] When `verify_capabilities=true`, Gateway must:
  - verify capability token validity
  - ensure action/resource matches scopes
  - enforce TTL and budgets
- [ ] Define and document the default capability behavior (`cap:default`).

### 1.4 Adapter hardening defaults
- [ ] File adapter:
  - sandbox required in prod
  - prevent path traversal edge cases
  - explicit allowlist patterns
- [ ] HTTP adapter:
  - deny-by-default host policy in prod OR explicit allowlist required
  - timeouts, max response size enforced

---

## 2) MetaRules Policy Enforcement — **Required for Beta**
### 2.1 Wire MetaRules into `POST /v1/vakya`
- [ ] Evaluate policy before dispatching to adapters.
- [ ] Deny actions cleanly with `ReasonCode::PolicyDenied`.

### 2.2 Approval workflow minimum viable
- [ ] If `DecisionType::PendingApproval`, return a structured response:
  - `status=pending_approval`
  - include approval requirement IDs
- [ ] Add endpoints:
  - [ ] `POST /v1/approvals/{approval_id}/approve`
  - [ ] `POST /v1/approvals/{approval_id}/reject`
  - [ ] `GET /v1/approvals/{approval_id}`

### 2.3 Policy configuration
- [ ] Simple static policy loading (JSON or YAML file).
- [ ] Document policy format.
- [ ] Provide at least 2 default sample policies:
  - deny delete outside sandbox
  - require approval for dangerous actions

---

## 3) API Stability & Compatibility
### 3.1 Versioning policy
- [ ] Define semantic version policy for the project.
- [ ] Define compatibility rules for:
  - VĀKYA schema changes
  - Gateway REST endpoints
  - Python SDK changes

### 3.2 OpenAPI completeness
- [ ] Ensure OpenAPI spec includes:
  - adapters
  - receipts
  - effects
  - merkle endpoints
  - approval endpoints (when added)

---

## 4) Evidence Plane Completeness
### 4.1 Receipt/effect semantics
- [ ] Document exactly what `EffectRecord` contains for each adapter action.
- [ ] Ensure effect capture includes sensible redaction hooks (for secrets).

### 4.2 Replay & rollback
- [ ] Add initial rollback endpoint:
  - [ ] `POST /v1/vakya/{vakya_id}/rollback`
- [ ] Store rollback plans in IndexDB (even if execution is manual in Beta).

---

## 5) Developer Experience (DX) — **Required for Beta**
### 5.1 CI pipeline
- [ ] GitHub Actions workflow:
  - `cargo fmt --check`
  - `cargo clippy` (deny warnings or at least report)
  - `cargo test`
  - Python checks: `python -m py_compile`, `pytest` (when tests exist)

### 5.2 Local developer setup
- [ ] `make` or `justfile` with:
  - `make test`
  - `make run-gateway`
  - `make lint`

### 5.3 Structured logging
- [ ] Document logging fields and how to enable debug.
- [ ] Add request IDs/tracing propagation docs.

---

## 6) Python SDK Beta Requirements
- [ ] Package metadata ready for pip install (`pyproject.toml` already exists).
- [ ] Provide:
  - [ ] Async client (`httpx.AsyncClient`) OR document that sync is intended.
  - [ ] Typed response models (optional but good for Beta).
- [ ] Tests:
  - [ ] unit tests for builders
  - [ ] gateway contract tests (smoke tests)

---

## 7) Documentation & OSS Hygiene — **Required for Beta**
- [ ] Add `LICENSE` file in repo root.
- [ ] Add `CONTRIBUTING.md`.
- [ ] Add `CODE_OF_CONDUCT.md`.
- [ ] Add `SECURITY.md`.
- [ ] Add `CHANGELOG.md`.
- [ ] Add a threat model doc:
  - attacker model
  - what signatures protect
  - what Merkle log protects
  - what adapters must defend against

---

## 8) Testing & Hardening
### 8.1 Adapter tests
- [ ] File adapter path traversal tests
- [ ] File adapter rollback tests
- [ ] HTTP adapter allow/deny host tests

### 8.2 Gateway integration tests
- [ ] Start gateway in-memory and submit:
  - file.write
  - file.read
  - http.get
- [ ] Verify:
  - receipt exists
  - effects exist
  - Merkle proof verifies

---

## Suggested Beta v0.01 Milestone Order
1. Enforce signature/capability gates behind config flags
2. Wire MetaRules allow/deny + pending approval response
3. Add minimal approval endpoints
4. CI + repo hygiene + changelog
5. Hardening tests + rollback endpoint
6. Python SDK: async client and tests
