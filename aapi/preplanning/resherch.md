# Research — AAPI as a Real-World Action Protocol

## 0) Goal of this research
You asked for a deep scan of:

- **What exists today** (agent tool protocols, M2M protocols, audit/evidence systems)
- **What AAPI needs** to become a durable protocol (AI→Machine, Machine→Machine, Human→Agent→Machine)
- **How to harden the architecture** so it stands against security, compliance, and scale requirements

This document focuses on **standards/specs/papers** that can be *directly reused* or *aligned with*, and the gaps AAPI uniquely fills.

---

## 1) What exists today (landscape)

### 1.1 Agent tool / app integration protocols
- **MCP (Model Context Protocol)**
  - **What it standardizes**: discovery + invocation of tools (`tools/list`, `tools/call`) using JSON Schema; transports (stdio/HTTP); optional OAuth-based authorization; strong emphasis on user consent and auditability.
  - **Why it matters for AAPI**: MCP is becoming the de-facto *LLM tool wiring* layer. AAPI can be implemented as an MCP server (or MCP tools can emit AAPI VĀKYAs).
  - **Key security lessons**:
    - Confused deputy risk in “proxy to third-party OAuth” patterns.
    - Scope minimization and progressive authorization.
  - **Refs**:
    - Specification: https://modelcontextprotocol.io/specification/2025-06-18
    - Security Best Practices (confused deputy + scopes): https://modelcontextprotocol.io/llms-full.txt

### 1.2 API description and machine-readable contracts
- **OpenAPI 3.1**
  - **What it standardizes**: HTTP API description with JSON Schema 2020-12 semantics.
  - **Why it matters**: AAPI Gateway can expose a public HTTP interface described via OpenAPI; also helps publish `body_type` schemas.
  - **Ref**: https://spec.openapis.org/oas/v3.1.2.html

- **AsyncAPI 3.0**
  - **What it standardizes**: event-driven APIs (Kafka/MQTT/WebSockets/AMQP/etc.) + message schemas.
  - **Why it matters**: AAPI can operate as a command/event fabric: VĀKYA commands + AEO/PRAMĀṆA events.
  - **Ref**: https://www.asyncapi.com/docs/reference/specification/v3.0.0

### 1.3 Event envelopes (portable “facts happened” schema)
- **CloudEvents (CNCF)**
  - **What it standardizes**: a universal envelope for events (`id`, `source`, `type`, `specversion`, etc.).
  - **Why it matters**: AEO (Effect Summary) and PRAMĀṆA (Receipt) can be emitted as CloudEvents for cross-system interoperability.
  - **Ref**: https://raw.githubusercontent.com/cloudevents/spec/main/cloudevents/spec.md

### 1.4 Observability correlation (traces/logs)
- **W3C Trace Context**
  - **What it standardizes**: propagation headers (`traceparent`, `tracestate`) to correlate distributed actions.
  - **Why it matters**: AAPI calls should be traceable across gateway → control plane → adapter → downstream systems.
  - **Ref**: https://www.w3.org/TR/trace-context/

- **OpenTelemetry logs data model**
  - **What it standardizes**: a common log record model; includes trace fields for correlation.
  - **Why it matters**: even if AAPI uses IndexDB, it will still integrate with standard observability stacks.
  - **Ref**: https://opentelemetry.io/docs/specs/otel/logs/data-model/

### 1.5 Identity (machine/workload identity) for M2M
- **SPIFFE**
  - **What it standardizes**: workload identity namespace (SPIFFE IDs) + SVIDs (X.509 or JWT) + Workload API.
  - **Why it matters**: AAPI KARTA in M2M mode needs a stable identity story that works across clouds and clusters.
  - **Ref**: https://raw.githubusercontent.com/spiffe/spiffe/main/standards/SPIFFE.md

### 1.6 Authorization + proof-of-possession
- **OAuth 2.0 Security BCP (RFC 9700)**
  - **What it standardizes**: current best practice threat model + mitigations.
  - **Why it matters**: if AAPI offers OAuth tokens for clients, you should adopt these best practices (esp. token replay, redirect risks).
  - **Ref**: https://www.rfc-editor.org/rfc/rfc9700.html

- **DPoP (RFC 9449)**
  - **What it standardizes**: proof-of-possession at HTTP layer (bind tokens to a key).
  - **Why it matters**: AAPI requests are high-impact; proof-of-possession reduces token replay and strengthens non-repudiation.
  - **Ref**: https://www.rfc-editor.org/rfc/rfc9449.html

- **HTTP Message Signatures (RFC 9421)**
  - **What it standardizes**: detached signatures over selected HTTP components.
  - **Why it matters**: AAPI can be “signed at transport level” even across proxies/TLS termination.
  - **Ref**: https://www.rfc-editor.org/rfc/rfc9421

### 1.7 Canonicalization (hash stability)
- **JSON Canonicalization Scheme (RFC 8785 / JCS)**
  - **What it standardizes**: deterministic JSON serialization for hashing/signing.
  - **Why it matters**: AAPI’s Sandhi canonicalization must be *cryptographically stable* to support receipts.
  - **Ref**: https://www.rfc-editor.org/rfc/rfc8785

### 1.8 Capability-based / attenuated authorization tokens
These are highly aligned with AAPI’s `adhikarana.cap` concept.

- **Macaroons (Google / NDSS)**
  - **Key idea**: bearer credentials with chained caveats for attenuation.
  - **Relevance**: expresses “caps with caveats” (TTL, constraints) naturally.
  - **Ref**: https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/

- **Biscuit**
  - **Key idea**: decentralized verification, offline attenuation, Datalog policies inside token.
  - **Relevance**: a strong candidate for an AAPI cap token format (practical, multi-language).
  - **Ref**: https://www.biscuitsec.org/

- **UCAN**
  - **Key idea**: user-controlled capability delegation, strong canonical encoding (DAG-CBOR), explicit “commands”.
  - **Relevance**: an existence proof that “capability + command” can be made into a portable protocol.
  - **Ref**: https://github.com/ucan-wg/spec

### 1.9 Policy engines / authorization DSLs
- **OPA / Rego (policy-as-code)**
  - **Relevance**: can serve as the “hard policy” layer if you want a mature DSL + tooling.
  - **Ref**: https://www.openpolicyagent.org/docs

- **Cedar (AWS)**
  - **Key idea**: analyzable authorization policies with bounded latency.
  - **Relevance**: aligns with AAPI’s emphasis on explainability + “deterministic governance”.
  - **Ref**: https://github.com/cedar-policy/cedar

### 1.10 Evidence, transparency, receipts (truth systems)
This cluster is extremely aligned with your **Evidence Plane**.

- **Certificate Transparency (RFC 9162)**
  - **Key idea**: append-only Merkle log + signed tree heads + inclusion/consistency proofs.
  - **Relevance**: AAPI IndexDB can evolve into a CT-like transparency log for non-repudiation and non-equivocation.
  - **Ref**: https://www.rfc-editor.org/rfc/rfc9162.html

- **Transparent Logs (tile-based)**
  - **Key idea**: efficient verification; “tile” optimization; clients can verify append-only behavior.
  - **Relevance**: design blueprint for IndexDB auditability.
  - **Ref**: https://research.swtch.com/tlog

- **SCITT (IETF draft)**
  - **Key idea**: general “signed statements + transparency service + receipt” architecture, content-agnostic.
  - **Relevance**: SCITT’s model maps directly to: VĀKYA (signed statement) + PRAMĀṆA (receipt) + IndexDB (transparency log).
  - **Ref**: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/

- **DSSE (Dead Simple Signing Envelope)**
  - **Key idea**: sign arbitrary bytes with an explicit “payload type” to prevent confusion attacks; avoids canonicalization.
  - **Relevance**: AAPI can use DSSE to sign canonical VĀKYA bytes (Sandhi output) + effect bytes.
  - **Ref**: https://github.com/secure-systems-lab/dsse

- **in-toto Attestation Framework**
  - **Key idea**: layered model (Predicate → Statement → Envelope → Bundle).
  - **Relevance**: AAPI AEO/PRAMĀṆA can align with “statement+predicate” structure for ecosystem compatibility.
  - **Ref**: https://raw.githubusercontent.com/in-toto/attestation/main/spec/README.md

- **SLSA**
  - **Key idea**: levels + provenance formats; stronger supply-chain evidence expectations.
  - **Relevance**: provides a mature vocabulary for “evidence quality” that can inform AAPI’s evidence levels.
  - **Ref**: https://slsa.dev/spec/v1.2/

- **Sigstore Rekor**
  - **Key idea**: transparency log for signed metadata; moving toward tile-based logs.
  - **Relevance**: operational proof that a public verifiable log is feasible; also shows practical limits (size caps).
  - **Ref**: https://raw.githubusercontent.com/sigstore/rekor/main/README.md

### 1.11 Audit log format (who did what) as a real deployed reference
- **Google Cloud Audit Logs**
  - **What it provides**: structured audit log entries answering who/what/where/when (serviceName, methodName, authn info, resource).
  - **Relevance**: strong evidence that “structured audit logs” are a baseline expectation; AAPI goes further by binding receipts+effects.
  - **Ref**: https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs

---

## 2) Where AAPI sits in the ecosystem (AI↔Machine / M2M / human-in-loop)

### 2.1 AAPI vs MCP
- **MCP**: standardizes *how models call tools*.
- **AAPI**: standardizes *what a real-world action is* (grammar, authority, evidence, effects).

**Strong positioning**:
- **AAPI can be implemented behind MCP tools**.
- MCP becomes a “front-end transport + UI/consent layer”; AAPI is the “truth + governance + execution fabric”.

### 2.2 AAPI vs “normal APIs” (OpenAPI/gRPC)
- Traditional APIs are **mechanism-bound** (each service defines its own semantics).
- AAPI is **semantic-bound** (same 7 roles everywhere), then mapped to mechanisms via adapters.

**Implication**:
- AAPI can be the universal *action envelope* that wraps existing OpenAPI/gRPC endpoints.

### 2.3 AAPI vs event systems (CloudEvents)
- CloudEvents is “**something happened**” envelope.
- AAPI is “**we intend to do X under authority Y**” + signed evidence of what occurred.

**Implication**:
- Emit AEO and PRAMĀṆA as CloudEvents to integrate with event routers.

---

## 3) What is missing today (the gap AAPI can own)

### 3.1 Missing standard: a universal action sentence
- **Problem**: Tool JSON has no universal slots for actor/resource/authority.
- **Consequence**: hard to audit, hard to govern, hard to learn, hard to share across domains.

### 3.2 Missing standard: effects as first-class truth
- **Problem**: logs are untrusted and inconsistent; they don’t bind to reality.
- **Consequence**: agents can’t learn from outcomes safely; auditors can’t verify.

### 3.3 Missing standard: receipts for every decision
- **Problem**: most systems record actions, but not cryptographically verifiable “decision receipts”.
- **Consequence**: non-repudiation and cross-org trust break down.

### 3.4 Missing standard: safe online learning in governance
- **Problem**: current “policy learning” is either absent or too ML-heavy/opaque.
- **Consequence**: systems don’t improve safely.

---

## 4) Concrete recommendations to make your architecture solid

### 4.1 Make Sandhi cryptographically rigorous
- **Recommendation**: define Sandhi output encoding as either:
  - **Option A (JSON)**: RFC 8785 JCS canonical JSON bytes, then hash/sign.
  - **Option B (binary)**: CBOR/COSE (SCITT-style) for compactness.
  - **Option C (envelope)**: DSSE signing over canonical bytes + explicit payloadType.

### 4.2 Make PRAMĀṆA receipts align with transparency log patterns
- **Recommendation**:
  - Produce receipts that can support **append-only proofs** (CT/SCITT style).
  - Introduce an “IndexDB root hash / signed tree head” concept if you want non-equivocation.

### 4.3 Adopt a mature capability token model
- **Recommendation**:
  - Prototype `adhikarana.cap` using an existing capability format (Biscuit / UCAN / Macaroons), or a minimal homegrown cap v0.
  - Keep room to swap formats later.

### 4.4 Adopt standard correlation headers
- **Recommendation**:
  - Carry `traceparent` and `tracestate` across all AAPI calls.

### 4.5 Provide a compatibility surface to become “the protocol”
- **Recommendation**:
  - **MCP server**: offer AAPI tools to LLM hosts.
  - **HTTP API + OpenAPI**: offer AAPI Gateway endpoints for M2M.
  - **Events + CloudEvents/AsyncAPI**: emit AEO/PRAMĀṆA to Kafka/etc.

---

## 5) Next synthesis output
This research feeds `preplanning/engineering.md`:

- **AAPI wire formats** (JSON-JCS vs DSSE vs COSE)
- **Identity & auth** (SPIFFE, OAuth BCP, DPoP)
- **Capability tokens** (Biscuit/UCAN/Macaroons)
- **Evidence plane hardening** (CT/SCITT/tlog patterns)

