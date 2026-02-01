# Engineering — Hardening AAPI into a Protocol (v0.1 → v1)

## 0) What this document is
This is the **engineering blueprint** to make your AAPI architecture “solid”:

- **Solid as a system**: secure, auditable, deterministic.
- **Solid as a protocol**: well-defined envelope, wire format, signing, versioning.
- **Solid as an ecosystem bridge**: AI tool calls (MCP), M2M (HTTP/OpenAPI), eventing (CloudEvents/AsyncAPI).

---

## 1) Outcomes (v0.1 deliverables)

- **Deliverable 1**: A stable VĀKYA request envelope (AAR) with canonicalization + hashing.
- **Deliverable 2**: A capability/authority format (`adhikarana.cap`) that enforces scope, TTL, budgets.
- **Deliverable 3**: A dispatcher + adapter contract with runtime enforcement hooks.
- **Deliverable 4**: IndexDB (append-only) storing:
  - **VĀKYA canon**
  - **AEO effects**
  - **PRAMĀṆA receipts**
- **Deliverable 5**: A public API surface:
  - **HTTP Gateway** (OpenAPI-described)
  - Optional: **MCP server** facade

---

## 2) Protocol boundary: what AAPI standardizes vs what it doesn’t

### 2.1 Standardize (must be stable)
- **AAR**: 7-slot envelope + metadata + signature container.
- **Sandhi**: canonicalization algorithm + hash definition.
- **PRAMĀṆA**: receipt schema + signature + reason codes.
- **AEO**: effect buckets + normalization.
- **Capability model**: at least minimal semantics (scope, TTL, budgets).

### 2.2 Do NOT standardize (keep pluggable)
- **`body` schema**: belongs to adapters/domains.
- **Policy language**: can be hard-coded rules, OPA, Cedar, etc.
- **Adapter implementation**: POSIX/Stripe/DB/etc.

---

## 3) Wire format & signatures (this is the biggest “make it solid” decision)

### 3.1 Requirements
- **Deterministic hashing**: `vakya_hash` must be stable across languages.
- **Non-confusable signatures**: signature must bind *type* + *payload*.
- **Proxy-safe**: signatures should survive TLS termination if needed.

### 3.2 Recommended v0.1 profile (simple + interoperable)

#### Profile: `AAPI-JSON-JCS-Ed25519`
- **Canonicalization**:
  - Sandhi output is serialized using **RFC 8785 (JCS)**.
- **Hash**:
  - `vakya_hash = sha256(jcs_bytes(vakya_canon))`
- **Signature**:
  - `sig = ed25519_sign(karta_private_key, vakya_hash)`

**Why**:
- JCS is widely implementable.
- JSON is debug-friendly.
- Ed25519 is fast and widely available.

### 3.3 Alternative profile (strong “signed envelope”)

#### Profile: `AAPI-DSSE`
- Use **DSSE** to sign canonical bytes, binding `payloadType` to the signature.
- This reduces “confusion attacks” and avoids embedding signature fields inside JSON objects.

**Good fit**:
- You already separate canon + hash + receipt.
- DSSE is used in supply-chain ecosystems (in-toto, Sigstore).

### 3.4 Future profile (compact + SCITT-aligned)

#### Profile: `AAPI-COSE/CBOR`
- Use **COSE Sign1** for signed statements.
- This aligns strongly with **SCITT** patterns (signed statement + receipt).

**Tradeoff**:
- More implementation complexity.

---

## 4) VĀKYA (AAR) schema hardening

### 4.1 Required top-level fields (recommendation)
- **`vakya_version`**: semantic version of envelope.
- **`vakya_id`**: idempotency key (client-generated UUID).
- **`v1_karta`**: `{pid, role, realm, key_id}`.
- **`v2_karma`**: `{rid, kind, ns}`.
- **`v3_kriya`**: canonical `domain.verb`.
- **`v4_karana`**: `{via?, adapter?}` (optional).
- **`v5_sampradana`**: recipient (optional).
- **`v6_apadana`**: source (optional).
- **`v7_adhikarana`**: `{cap_ref|cap, policy_ref, ttl_ms, budgets, approval_lane}`.
- **`body_type`**: `{name, version}`.
- **`body`**: free-form payload.
- **`meta`**:
  - **`traceparent`/`tracestate`** (W3C Trace Context)
  - timestamps (`submitted_at`, etc.)

### 4.2 Sandhi canonical form fields
- **`vakya_canon`**: canonical normalized object.
- **`vakya_hash`**: sha256 of canon bytes.
- **`sandhi_report`**: normalization details (for debugging + audit).

---

## 5) Authority model (Adhikaraṇa) — making it real

### 5.1 What you need in v0.1
- **Scope**: allowed `kriya` patterns + allowed namespaces.
- **Budgets**: money, calls, bytes, writes, rows.
- **TTL**: expiry + per-call deadline.
- **Audience binding**: token intended for a specific gateway/service.

### 5.2 Recommended implementation paths
- **Path A (fastest)**: simple signed `cap` JSON object (JCS + Ed25519), embedded or referenced.
- **Path B (robust)**: adopt an existing capability token:
  - **Biscuit**: offline attenuation + policy checks.
  - **UCAN**: explicit capability/command model.
  - **Macaroons**: caveats.

### 5.3 OAuth integration (optional)
If you expose AAPI as an HTTP service for third parties:
- Follow **OAuth Security BCP (RFC 9700)**.
- Add **DPoP (RFC 9449)** for proof-of-possession where feasible.
- Consider **HTTP Message Signatures (RFC 9421)** for end-to-end request integrity across proxies.

---

## 6) Control Plane implementation plan

### 6.1 Phases (per request)
- **Phase 1**: parse + validate 7 slots.
- **Phase 2**: verify KARTA signature.
- **Phase 3**: Sandhi + Bidshit → produce canon + hash.
- **Phase 4**: resolve authority (`adhikarana`) → caps + budgets + TTL.
- **Phase 5**: deterministic decision (ALLOW/DENY/APPROVAL/THROTTLE/STEP_UP).

### 6.2 Policy implementation strategy
- **Hard rules**: code-defined denylist/allowlist for forbidden kriyās/namespaces.
- **MetaRules tree**: bounded numeric thresholds only.
- **Optional later**:
  - OPA/Rego or Cedar as an external PDP.

### 6.3 Critical security requirement
- **Never execute before canonicalization** (you already defined this invariant).

---

## 7) Execution Plane implementation plan

### 7.1 Adapter interface (must be enforced)
- **`validate(vakya)`**
- **`plan(vakya)`** (optional)
- **`execute(vakya, runtime_ctx)`**
- **`emit_effects(result)`**
- **`hash_result(result)`**

### 7.2 Runtime enforcement
- **Budgets are enforced twice**:
  - **Pre-check** (reject early)
  - **Runtime** (stop mid-run)

### 7.3 Sandbox patterns by domain
- **OS**: container/VM + allowlisted mounts + seccomp/AppArmor.
- **Network**: egress allowlist + rate/byte caps.
- **DB**: table allowlist + row cap + tx timeout.
- **Finance**: idempotency + max amount + recipient allowlist.

---

## 8) Evidence Plane (IndexDB) — engineering it like a transparency system

### 8.1 Minimal storage tables (SQLite v0.1)
- **`vakya_event`** (append-only)
  - `vakya_hash` (pk)
  - `vakya_canon_bytes`
  - `received_at`
  - `decision` (ALLOW/DENY/APPROVAL)
  - `decision_reason_codes`
- **`effect`**
  - `effect_hash` (pk)
  - `effect_bytes` (normalized)
  - `vakya_hash` (fk)
- **`pramana`**
  - `receipt_id` (pk)
  - `vakya_hash` (fk)
  - `effect_hash` (nullable)
  - `policy_ref`
  - `signed_receipt_bytes`

### 8.2 “Proof mode” upgrades
- **Upgrade A**: hash-chain each event: `prev_hash` → “tamper evident”.
- **Upgrade B**: Merkle tree + signed tree heads (CT style).
- **Upgrade C**: full SCITT-style transparency service receipts.

### 8.3 Logging interoperability
- Emit a structured log record per call aligning with:
  - Google Cloud Audit Log style “who did what where when”
  - OTel log model + trace correlation

---

## 9) Public API surface (AAPI Gateway)

### 9.1 HTTP endpoints (suggested)
- **`POST /vakya`**: submit AAR.
- **`GET /vakya/{vakya_hash}`**: fetch canon + decision + links.
- **`GET /vakya/{vakya_hash}/receipt`**: fetch PRAMĀṆA.
- **`GET /vakya/{vakya_hash}/effects`**: fetch AEO.
- **`GET /events`**: filtered event view (by kriya/ns/karta/time).

### 9.2 Async/event output
- Emit:
  - **`aapi.vakya.decision`**
  - **`aapi.vakya.effect`**
  - **`aapi.vakya.receipt`**
- Recommended envelope: **CloudEvents**.

---

## 10) AAPI as “AI↔Machine / M2M / human-in-loop protocol”

### 10.1 AI↔Machine
- Provide an **MCP server** where each tool call results in a VĀKYA submission.
- Tool schemas become “front-end UX”; VĀKYA remains the canonical truth record.

### 10.2 Machine↔Machine
- Use the HTTP gateway + OpenAPI.
- Use SPIFFE identities for workloads (KARTA pid).

### 10.3 Human command / approvals
- Model approval as:
  - **a decision outcome** (`REQUIRE_APPROVAL`) + receipt
  - followed by a **new VĀKYA** that grants approval / escalated cap

---

## 11) Security threats checklist (mapped to your invariants)

- **Threat: token replay / stolen bearer tokens**
  - **Mitigate**: DPoP, short TTL, audience binding.

- **Threat: confused deputy (proxy OAuth)**
  - **Mitigate**: per-client consent binding, strict redirect URI handling, scope minimization.

- **Threat: canonicalization ambiguity**
  - **Mitigate**: RFC 8785 JCS (or DSSE over bytes), versioned Sandhi rules.

- **Threat: adapter escape**
  - **Mitigate**: sandbox + runtime budgets + strict allowlists.

- **Threat: log tampering**
  - **Mitigate**: append-only + signed receipts + (future) Merkle tree heads.

---

## 12) Roadmap

### 12.1 v0.1 (single node)
- JCS canonicalization + hash + Ed25519 signatures
- SQLite IndexDB
- 1–2 adapters (POSIX read/write + HTTP request)
- AEO + PRAMĀṆA returned for every call

### 12.2 v0.2
- Pluggable cap token format (Biscuit/UCAN option)
- CloudEvents emission
- OpenAPI spec published

### 12.3 v1
- Transparency log mode (Merkle / SCITT-like receipts)
- Federation / witness nodes

