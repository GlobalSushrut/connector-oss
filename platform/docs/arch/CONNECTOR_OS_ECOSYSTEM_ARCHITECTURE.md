# Connector OS — Govern the Ecosystem. Prove Every Guarantee.

**Status:** Ecosystem government SoT. Does not replace [CONNECTOR_PRODUCT_PROMISE.md](CONNECTOR_PRODUCT_PROMISE.md), [CONNECTOR_CAPABILITY_STANDARD.md](CONNECTOR_CAPABILITY_STANDARD.md), or [CONNECTOR_FULL_ARCHITECTURE.md](CONNECTOR_FULL_ARCHITECTURE.md).

**Live report:** `GET /api/v1/runtime/ecosystem` · `connectorctl govern ecosystem`

**Rule:** where an industry-standard mechanism exists, that project is the controller. Connector owns the semantics those projects do not: intelligence identity, contract, authority, PATE admission, memory validity, cease fan-out, and the binding between evidence records.

Every claim below is **HAVE**, **PARTIAL**, or **TARGET**. TARGET is not finished. The conformance report does not print PASS for a TARGET check.

```text
IDENTITY → CONTRACT → AUTHORITY → CONTEXT + MEMORY → ADMISSION
    → RUNTIME ENFORCEMENT → EFFECT → EVIDENCE → CONSEQUENCE
```

Four tests for every component: usable by an operator, credible because a named upstream owns the mechanism, provable by a command or receipt, composable because Connector does not replace that upstream.

The pitch is not the diagram. It is: run the report, break a contract, invoke Cease, read the receipt.

One critical task, end to end — what the model sees, what the operator configures, and which reports come back — is [GOVERNED_CRITICAL_AGENT.md](GOVERNED_CRITICAL_AGENT.md).

Prediction of the next state is [AGENTIC_WORLD_DYNAMICS.md](AGENTIC_WORLD_DYNAMICS.md). V0 reads DIM, PATE, and the broker. It does not admit.

**Operator surface.** Call Connector. OpenShell, IAM, Firecracker, OPA, SPIRE, OpenTelemetry, and cosign are the seven backends. `connectorctl govern backends` lists them. `operator_runs_it` is false on every row. Connector calls the tool. A missing binary is `not_installed`. Connector does not emulate it.

**Deployment truth.** `connectorctl govern deploy-verify
[linux-kvm|kubernetes]` is fail-closed and separate from `/readyz`. It requires
a Keycloak OIDC/JWKS token verification, a fetched SPIRE SVID, a successful
OpenShell policy set, OPA inside that OpenShell operation, a complete
Firecracker create/start → pause → destroy sequence through verified microd, an
accepted OTLP export, and a successful cosign `verify-blob`. Presence and
configuration are blockers, not readiness. The Kubernetes profile can be
functionally ready but is not production-eligible while NVIDIA labels its
OpenShell chart experimental.

---

## Why install it

Without Connector an operator already has an LLM, MCP, a sandbox, IAM, a policy engine, a microVM, telemetry, and a memory store, and still has to answer, by hand: which intelligence acted, under which contract and grant, with which memory epoch, why the action was admitted, what effect occurred, whether revocation reached every layer, and how to prove the chain.

Connector keeps those tools. It binds them.

OpenShell knows execution. Firecracker knows machines. OPA knows policy. SPIFFE knows workloads. OIDC knows users. OpenTelemetry knows telemetry. MCP knows tool calls. None of them has to know: this intelligence, under this contract, authority, and memory epoch, was admitted to this consequence, inside this runtime, produced this observed effect, proven by this evidence.

That sentence is the reason for the project.

---

## One government

PATE admits intent. The policy compiler projects `AgentContractV2` + the live grant + the cease generation into an OpenShell bundle. OPA inside the supervisor evaluates that bundle at the socket. If PATE allowed the intent and the proxy denied the socket, deny wins and the mismatch is evidence. OpenShell is not a second authority. Its sandbox id is a runtime handle, not the agent.

Operator JWT revocation (`jti`) is a different fence from Cease. Cease does not log the human out.

---

## 1. Intelligence identity — PARTIAL

**Problem.** A JWT subject, a SPIFFE ID, and a sandbox id do not say which intelligence is acting.

**Have.** `IntelligencePrincipalV2` and `AgentIdentityEnvelopeV2`, minted at register in `platform/server/src/kernel/agent_principal.rs`. Address cage refuses agent-as-host.

**Proof today.** Two principals yield two contract digests. The public test — same user, same machine, same model, different admissible effects, two receipt chains — is TARGET.

**Connector adds.** The binding of an intelligence to contract + authority epoch + memory epoch + evidence. It does not replace OIDC or SPIRE.

## 2. Contract — PARTIAL

**Problem.** A system prompt is not a boundary.

**Have.** `compile_contract` builds `AgentContractV2`: capabilities, denied operations (default `modify_contract`, `ambient_shell`), filesystem read/write, `network_allow`, `network_default: deny`, `receipt_required`, `contract_digest_sha256`. The digest is stamped on `ActionBinding`.

**Have, projection.** `compile_openshell_projection` emits an OpenShell policy document `version: 1`: `filesystem_policy` and `network_policies` (host, port 443 unless the allow entry names a port, binaries `/usr/bin/**` and `/usr/local/bin/**`). Digest, generation, deny-default, and denied operations stay in comments because those fields are Connector's, not OpenShell's.

**Proof target.** Allow `api.example.com`, attempt `evil.example`, and show contract digest, PATE decision, compiled policy digest, runtime denial, and effect receipt in one chain.

**Connector does not invent** a seccomp language, a Landlock dialect, or an L7 engine.

## 3. Authority — PARTIAL

**Problem.** Identity is not permission.

**Have.** `AuthorityRoot`, `GrantRef`, attenuation, `RevocationTombstone`, dual-written with legacy `WorldGrant`. HITL denies a one-byte change after approval (Pillar 3).

**Proof target.** Same prompt, same tool: grant succeeds, attenuated grant narrows, revoked grant denies, no model restart.

## 4. PATE admission — PARTIAL

**Problem.** A socket policy cannot decide whether this intelligence should attempt the consequence.

**Have.** `AugmentedTaskUnit` in `platform/server/src/substrate/pate.rs` wraps talk, tool, CONP, and A2A admission. DIM, Knot, CRK, and SVF do not mint Allow. Stale cease generations fail the admit.

**Upstream.** OPA graduated from the CNCF on 29 January 2021. It stays the runtime policy engine inside OpenShell. Connector does not add Cedar or Cerbos beside it.

**Have, mismatch record.** When PATE has admitted and the node L7 allowlist then denies the socket, `note_runtime_deny_after_admit` stores `connector.policy_mismatch.v1` with `deny_wins: true` and `openshell_opa: false`. Explain shows that row as `enforcement_mismatch`. An OpenShell OPA deny is the same shape only when `runtime_controller` is `openshell`.

**Have, OpenShell log.** Cease also runs `openshell logs --source sandbox`. A line is recorded as `runtime_controller: openshell` with `openshell_opa: true` only when it contains `denied` and `by policy`, and the latest PATE verdict is `proceed`. Any other deny keeps `openshell_opa: false`.

**Proof target.** The same unauthorized call succeeds on the lab subprocess and is blocked under the supervisor.

## 5. OpenShell execution boundary — PARTIAL

**Problem.** The agent must not enforce its own restrictions.

**Upstream.** NVIDIA OpenShell supervisor: unprivileged child, Landlock, seccomp, network namespace, CONNECT proxy, in-process OPA, credential injection, policy generation that closes stale tunnels. Compute drivers: Docker, Podman, Kubernetes, MicroVM. The OpenShell gateway is a lifecycle driver, not Connector’s authority plane.

**Have.** OpenShell is a Connector backend. The operator does not run the `openshell` CLI. Cease calls `openshell version`, `openshell policy set <CONNECTOR_OPENSHELL_SANDBOX> --policy <file> --wait --timeout 20` when that name is set, `openshell sandbox create --policy <file> -- true` when `CONNECTOR_OPENSHELL_CREATE=1`, and `openshell logs --source sandbox`. `pushed` or `created` is true only when that process exits 0. A missing binary is `not_installed`. The sandbox id is a runtime handle, not the agent. Connector does not vendor OpenShell and does not emulate the supervisor or OPA.

**Proof target.** The same unauthorized call succeeds on the lab subprocess and is blocked under the supervisor, with the denial id on the consequence spine.

## 6. Runtime adapter — PARTIAL

**Problem.** One sandbox product cannot outlive one sandbox.

**Have.** `probe_all` reports four runtimes: Firecracker (delegates to `FirecrackerBackend`), container (docker binary present or not; DockerLab plugin cage already exists), subprocess lab (Landlock/seccomp in `linux_hardening.rs`), OpenShell (probe above). Operations named on the catalog: `probe`, `create`, `exec`, `push_policy`, `pause`, `destroy`, `measure`. Create/exec/destroy for OpenShell and a unified pause across every tier are TARGET. Plugin `IsolationRuntime` (`Subprocess | DockerLab | Microvm | Wasm`) stays the plugin cage and is not deleted.

**Tiers, one contract.**

| Posture | Stack | Boundary |
|---------|--------|----------|
| Harden | Firecracker MicroCell + OpenShell supervisor inside the guest | hardware + supervisor |
| Pilot | OpenShell on Docker or Podman | shared kernel, supervisor policy |
| Lab | existing subprocess + Landlock/seccomp | explicit weak posture; SOAS `playground_demo` stays this |

**Proof target.** One contract on Docker and on Firecracker, identical identity, authority, admission, and receipt shape.

## 7. Firecracker — PARTIAL when the host probe is ready, otherwise TARGET

**Have.** Vendored Firecracker + jailer on x86_64. MicroCell default is vsock-only (no TAP). `fanout_cease` calls `micro_cell::pause` when a MicroCell is stored for the agent, and records `no_microcell` when it is not. A pause error is stored as the VMM returned it.

**Upstream.** Firecracker is the microVM VMM. Connector does not ship another hypervisor.

**Host membrane.** `connector-kerneld` (eBPF, nftables, systemd `IPAddressAllow`) cages the `connectord` process. That is not the guest sandbox.

## 8. Cease — PARTIAL

**Problem.** Stopping a request is not revoking an autonomous system.

**Have.** `kernel_cease` bumps the context-broker generation, voids `ctx_tok`, aborts in-flight LLM streams, releases hop reservations, and writes `CeaseReceiptV1`. It now also seals the memory epoch, stores the policy generation, and pauses a bound MicroCell. The latest cease record includes a `fanout` object. OpenShell tunnels are reported `not_cut_no_supervisor_session` until a supervisor session exists.

**Proof target, the flagship demo.**

1. A multi-step effect is in flight.
2. The operator invokes Cease.
3. Generation increments.
4. Context is stale.
5. A new admit fails `stale_generation`.
6. The network tunnel dies.
7. The runtime pauses.
8. The sealed memory epoch is not injected as live context.
9. `CeaseReceiptV1` plus `fanout` lists the sequence.
10. The model may still say “continue.” The system answers `DENIED` / `stale_generation`.

**Have, proof.** `connectorctl govern cease-proof <agent-pid>` and `GET /api/v1/runtime/cease-proof/:agent_pid` return `connector.cease_proof.v1`. A step is `present` only from stored records or from `generation_is_live`, the same comparison `assert_live_generation` uses. That read does not increment the post-cease retry count. Step 1 is `present` when the cease receipt's `hops_cancelled` is greater than zero. Step 10 is `present` when a continue that still carries `generation_id_ceased` would be `DENIED` / `stale_generation`. No model is called. It stays `target` until both the ceased generation and the live broker generation are known. The object status is `PARTIAL` or `TARGET`. It is not PASS.

## 9. Memory epochs — PARTIAL

**Problem.** Retrieval answers what to remember. It does not answer whether that memory is still authorized.

**Have.** VAC `MemPacket`, Packet DNA, CRK `MemorySequenceDnaV1`, agent-memory capsule, evidence chain, `MomentProof`, context rollup (fade raw text, keep consequence), COPG for the operation graph.

**Have, seal.** After cease, `injection_allowed` is false while the live broker generation equals `sealed_generation`. `inject_agent_memory_capsule` then skips the capsule. The bytes are not deleted.

**Not a vector database.** Stores and retrievers stay stores and retrievers.

## 10. Consequence spine — PARTIAL

**Problem.** An investigator should not reassemble fourteen logs by hand.

**Have, separate.** `IntelligenceReceiptV2`, `MomentProof`, thin SVF `EffectReceipt`, `ConsequenceLease` (authorization, not history), WitnessCtl HMAC, books journal, forensic package, AACR (`connector.aacr.v1`) as the compliance epoch, zero-trust Ed25519 tool ticket, OpenTelemetry export at `/actionlog/export/otel`.

**Have, explain.** `connectorctl govern explain <receipt-id>` and `GET /api/v1/runtime/explain/:receipt_id` load a cease receipt or an IIA receipt. A cease receipt carries `agent_pid`. An IIA receipt carries `principal_id`; explain resolves that to the agent key in `intelligence_principal_v2` and then walks authority (WorldGrant and AACR head) → PATE task (`pate_atu_v1`) → memory-epoch seal → MomentProof context root → stored OpenShell projection → runtime fan-out → effect digest → W3C `trace_context` → signature. A step stays `absent` when that row is missing. `enforcement_mismatch` is `none` until a deny-wins record exists. A missing receipt returns `found: false`. The workload id is a SPIRE X.509 SPIFFE ID when `spire-agent api fetch x509` exits 0. Otherwise it is the cell URI, marked `partial`. A fetched SPIFFE ID is not the agent.

**Target.** One signed spine that fills the absent steps from AACR and MomentProof without a new evidence schema. AACR stays the compliance epoch.

## 11. Three identities — PARTIAL

| Identity | Controller | Status |
|----------|------------|--------|
| Operator | OIDC, OAuth 2.0 + PKCE, JWT (`jti`) verified by `auth::verify_token`, SCIM 2.0, TOTP, node mTLS. `GET /runtime/explain` records `sub` and `jti` from that verified token. | HAVE in `platform/server/src/auth/` |
| Workload | SPIFFE SVID via SPIRE (CNCF graduated 22 August 2022). `spire-agent api fetch x509 -socketPath $SPIFFE_ENDPOINT_SOCKET` when that socket is set. The id is recorded only if the process exits 0 and prints `spiffe://`. | PARTIAL. Connector does not issue SVIDs. With no socket, explain keeps the cell URI and marks it partial |
| Intelligence | `AgentIdentityEnvelopeV2` | HAVE |

A JWT subject is not an agent. A SPIFFE ID is not an agent. An OpenShell sandbox id is not an agent. When explain has a verified JWT `sub`, a fetched `spiffe://` id, and an intelligence id, it stores `identities.binding.digest_sha256`, a SHA-256 commitment of those three strings, and `identities.binding.court`, an Ed25519 `SignedPayloadV2` from the platform key (`SigningTierV2::Ed25519Court`) over that same digest. The signed body sets `authorizes` to false. Changing that field fails verification. This signature does not admit the effect. The effect signature stays on `IntelligenceReceiptV2`.

## 12. Standards are the controllers

| Problem | Controller | Connector | Status |
|---------|------------|-----------|--------|
| Agent sandbox | NVIDIA OpenShell CLI: `version`, `sandbox create --policy`, `policy set`, `logs --source sandbox` | compile `AgentContractV2` into policy schema version 1. Do not vendor the supervisor. | PARTIAL |
| Network / L7 | OPA/Rego inside OpenShell (CNCF graduated 29 January 2021) | the policy file is the input. A log line counts only when it says `denied` and `by policy`. Connector does not run `opa eval` and does not mint Allow. | PARTIAL |
| Hardware isolation | Firecracker + jailer | posture and lifecycle | PARTIAL |
| Dense tier | OCI via OpenShell’s Docker/Podman driver | same contract | TARGET |
| Kernel floor | Linux namespaces, cgroups, seccomp, Landlock, nft | do not grow a second filter on paths OpenShell covers | PARTIAL |
| Workload identity | SPIRE `spire-agent api fetch x509` | record the fetched SPIFFE ID; do not issue SVIDs | PARTIAL |
| Operator IAM | OIDC / OAuth / JWT / SCIM / mTLS | bind operator to the call | HAVE |
| Telemetry | OpenTelemetry and W3C Trace Context (CNCF graduated 21 May 2026) | effect trace from `trace_context`. `traceparent` on the explain request is `investigator_trace` and is not the effect. | PARTIAL |
| Tool wire | MCP | admit before transport | PARTIAL |
| Agent wire | A2A (auth stays OAuth/OIDC at HTTP) | admit before transport | PARTIAL |
| Supply chain | Sigstore / cosign. `cosign version`, then `cosign verify-blob --signature` when `CONNECTOR_COSIGN_BLOB` and `CONNECTOR_COSIGN_SIGNATURE` are set. Optional `--key` or `--certificate`. `verified` is the exit code. | bind digest to consequence | PARTIAL |
| Evidence signature | Ed25519 (`SigningTierV2::Ed25519Court`) | HMAC is lab only. The three-id commitment uses the same signer and does not authorize. | PARTIAL |
| Intelligence, grants, PATE, MemPacket epochs, cease fan-out, reconstruction | Connector | the sentence in “Why install it” | mixed, see sections above |

Wasm plugins stay Wasmtime + WASI, TCP/UDP off. That cage is not the agent body.

## 13. What Connector does not build

Another seccomp language, Landlock policy system, L7 engine, VMM, SPIRE, agent JWT, trace format, MCP, A2A, or generic IAM.

Also not rebuilt: PATE, `compile_contract`, AACR, COPG, the zero-trust handshake, the context broker, or operator JWT.

Existence test for any new subsystem:

1. A mature open-source project already solves it → integrate it.
2. A standard can express it → use the standard.
3. Connector is only renaming an existing abstraction → delete ours.
4. It preserves identity, authority, admission, revocation, memory validity, consequence, or evidence across systems that do not share those semantics → it belongs here.

## 14. Conformance — machine-readable, not a slogan

`connectorctl govern ecosystem` returns `connector.ecosystem_conformance.v1`. `connectorctl govern explain <receipt-id>` returns `connector.explain.v1`.

Checks: `identity`, `contract`, `authority`, `pate`, `openshell`, `runtime`, `firecracker`, `cease`, `memory`, `consequence`, `three_identities`.

Status is PARTIAL or TARGET. PASS is reserved until the check is enforced end to end. The unit test `report_never_marks_openshell_or_explain_as_pass` locks that.

## 15. Reference demo — TARGET

Create agent → mint identity → bind contract → issue grant → PATE allow → compile projection → effect → signed receipt → MemPacket → Cease → generation + 1 → context dead, admit dead, memory sealed, MicroCell paused when one exists → ask the model to continue → `DENIED` / `stale_generation`.

The continue-after-cease admit failure is `continue_after_cease`: the ceased generation is not live, so the answer is `DENIED` / `stale_generation`, and the memory seal exists. The scripted demo that drives OpenShell and prints one spine does not.

## 16. Reviewer path

Run these. Read the status. Do not treat TARGET as done.

| Check | What the operator runs | What Connector calls |
|-------|------------------------|----------------------|
| Backends | `connectorctl govern backends` | the seven rows below |
| Deployment | `connectorctl govern deploy-verify linux-kvm` | real operations from all seven backends; exits nonzero on any blocker |
| Conformance | `connectorctl govern ecosystem` | HAVE / PARTIAL / TARGET. PASS is unused. |
| One effect | `connectorctl govern explain <receipt-id>` | JWT, SPIRE fetch, W3C `traceparent`, SHA-256 commitment |
| Revocation | `connectorctl govern cease-proof <agent-pid>` | generation fence, OpenShell policy, Firecracker pause |
| Sandbox | nothing | `openshell` version, policy set, sandbox create, logs |
| Policy | nothing | OPA inside OpenShell. Connector does not run `opa`. |
| Workload | nothing | `spire-agent api fetch x509` when the socket is set |
| Supply chain | nothing | `cosign verify-blob` when the blob and signature paths are set |
| Hardware | nothing | Firecracker probe. `seven-pillars-host-attach-proofs.sh` is the host proof. This process does not set `military_court_ready`. |

What is still TARGET, on purpose: a scripted continue-after-cease demo, the same contract enforced on Docker and on Firecracker, and any claim of bank or military certification. The three-id commitment is signed with the platform Ed25519 key when those three ids are present. That signature is not a certification and not an authorization.

## 17–19. How outsiders should judge it

Success is not a star count. It is: another runtime implements the adapter, another framework passes conformance, a security engineer verifies Cease from the receipt, an auditor reconstructs one effect from existing records, and an OpenShell upgrade does not change `AgentContractV2`.

## 20. Production gate

`connectorctl govern ecosystem` includes `connector.production_gate.v1`.

**Bank-control** is ready only when the node is not a playground, the posture is production (or airgap, defense-strict, unbypassable, staging), `CONNECTOR_JWT_SECRET` is at least 32 characters, and no break-glass flag is on (`CONNECTOR_ALLOW_IN_PROCESS_EFFECTS`, guest egress, host MCP broker, dev auth bypass, LLM stub, insecure TLS, and the rest listed in `production_gate.rs`). That is a fail-closed self-host membrane. It is not a PCI DSS, SOC, or regulator certificate.

**Military-court** is ready only when bank-control is ready, Firecracker probes ready, an OpenShell supervisor is bound (`ready`, which stays false until one is), and `CONNECTOR_HOST_ATTACH_REPORT` (default `/tmp/connector-host-attach-proofs.json`) has `military_court_ready: true` from `platform/scripts/seven-pillars-host-attach-proofs.sh`. This process does not set that flag. `CLAIM_MILITARY_COURT=1` is `claim_refused` when any of those are missing. Partner SIL certification stays with the partner. See [COURT_GRADE_CLAIMS.md](COURT_GRADE_CLAIMS.md).

## 21. Product promise

Aligned with [CONNECTOR_PRODUCT_PROMISE.md](CONNECTOR_PRODUCT_PROMISE.md):

> Connector governs the path from intelligence identity to real-world consequence using explicit authority, external enforcement, revocable generations, and reconstructible evidence.

It does not promise correct model reasoning or absolute security. Soft-fail and playground mode stay lab posture. An outsider evaluates the claim by running `connectorctl govern ecosystem` and reading which rows are still TARGET.
