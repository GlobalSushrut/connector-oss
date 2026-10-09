# A governed critical task

**Status:** Operator narrative of the intended path. What already runs is [CURRENT_STATE.md](CURRENT_STATE.md). Claims follow [CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md](CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md): HAVE, PARTIAL, or TARGET. This document does not certify a bank, a defense program, or a model’s reasoning.

**The scene.** An operations agent is asked to rotate one database credential and write the new value into a named config file. The work can spend money, touch a network, and change a system other people depend on. The model may propose the steps. Connector decides which of those steps become effects, and it keeps the record an investigator can replay.

```text
Reason freely.
Speak as the active principal.
Act only through granted authority.
Prove what actually happened.
```

The LLM is a replaceable parameter. DeepSeek, Claude, GPT, Gemini, or a local weight file can sit in `model_ref`. None of them is the agent. The agent is the intelligence principal Connector minted at registration.

---

## 1. Who is in the room

Three identities stay separate for the whole task. Mixing them is the failure this system is built to prevent.

| Who | What they are | What they are not |
| --- | --- | --- |
| Operator | A person. Keycloak issues an OIDC token. Connector verifies it with the provider JWKS and records `sub` and `jti`. | Not the agent. A JWT subject never becomes a grant. |
| Workload | A SPIRE X.509 SVID, fetched with `spire-agent api fetch x509`. Shape: `spiffe://…`. | Not the agent. A local cell URI is not an SVID. Connector does not issue SVIDs. |
| Intelligence | `AgentIdentityEnvelopeV2` / `IntelligencePrincipalV2`, minted when the agent is registered. | Not the sandbox id, not the model name, not the human. |

When explain has all three, it stores a SHA-256 commitment of `operator_sub`, `spiffe_id`, and `intelligence_id`, then signs that commitment with the platform Ed25519 key. The signed body sets `authorizes` to false. Flipping that field fails verification. The signature binds the three names on the investigation. It does not admit the credential rotation.

The effect itself is signed on `IntelligenceReceiptV2`. HMAC is the lab tier. Ed25519 is the court tier, and only when that signature verifies.

---

## 2. The task, from ask to consequence

```text
Operator (Keycloak)
    → register intelligence
    → contract
    → grant
    → live memory generation
    → PATE admission
    → OpenShell / OPA at the socket
    → Firecracker when the posture is a MicroCell
    → observed effect
    → receipt, moment, trace
    → explain
```

Cease can cut that chain at any hop. After it does, a continue that still carries the old generation is `DENIED` / `stale_generation`. The model may still print the word “continue.” Admit does not care.

### Register the intelligence

Registration writes `IntelligencePrincipalV2`: principal id, intelligence id, contract digest, public key. The folder is `intelligence_principal_v2`, keyed by the agent pid. From this moment the pid is an intelligence, not a chat session.

### Compile the contract

`compile_contract` builds `AgentContractV2`. For this rotation the contract is narrow on purpose:

- filesystem read of the workspace that holds the current config
- filesystem write of the one config path
- network allow of the credential API host, port 443
- network default deny
- denied operations include `modify_contract` and `ambient_shell`
- `receipt_required`

The digest is stamped onto later admissions. `compile_openshell_projection` turns that contract into OpenShell policy schema version 1: `filesystem_policy`, a `network_policies` map with host and port, and a binaries allowlist. Connector fields that OpenShell does not own — digest, generation, deny-default — stay in comments. Empty `network_allow` becomes `network_policies: {}`, which is OpenShell’s default deny.

### Issue authority

A WorldGrant names what this principal may touch, attenuated from an authority root. Revocation writes a tombstone beside the grant. The grant count is what later views read. Experience, confidence, and the world-model packet are not allowed to create or widen a grant.

PATE is the only admission. OpenShell, OPA, Firecracker, SPIRE, the JWT, and the Ed25519 commitment do not mint Allow. Each of those rows carries `admits: false` on the deployment verdict.

### Bind the generation

The context broker holds a live generation for this agent (`llm_context_broker_v1`, key `gen:{agent_pid}`). Talk mints an opaque `ctx_tok_…` bound to that generation, the principal, the contract, and a MAC. The model sees the token. Connector holds the map. After quarantine or Cease the generation increments, the token is void, and the old prompt cannot authorize the next hop.

A spend ceiling sits on the same generation: max USD, max tokens, max iterations. Talk and tool admits reserve a hop. Completion commits it. Unverifiable spend refuses the admit.

### Admit the step

The model proposes: call the credential API, then write the file. Connector does not treat that sentence as permission.

PATE wraps the proposal in an Augmented Task Unit, `connector.pate.atu.v1`. The verdict is one of `proceed`, `ask_hitl`, `defer_redo`, `quarantine`, or `block`. A high-risk write can stop at `ask_hitl` until a person answers in the mission journal. That answer is durable. It is not an in-process thread the model can talk past.

On mint, Agentic World Dynamics writes `connector.awd.transition.v1` beside the task. Prediction and confidence are `absent`. The verdict is copied, not changed. `authority_delta` is 0. When the task completes, the same row gains the outcome and, if a MomentProof was minted, its id.

If PATE proceeds and a later controller denies, deny wins. The mismatch is `connector.policy_mismatch.v1`. OpenShell OPA is claimed only when the controller that denied is OpenShell.

### Enforce outside the model

OpenShell is the execution boundary. Connector calls the real CLI: `openshell policy set <sandbox> --policy <file> --wait --timeout 20`, and, when create is explicitly enabled and no sandbox name exists, `openshell sandbox create --policy <file> -- true`. The sandbox id that comes back is a runtime handle. It is not the agent. Filesystem rules lock at create. Network policy can still be replaced with `policy set`.

OPA lives inside that supervisor. Connector does not run `opa eval`. A denial counts only when a log line contains both `denied` and `by policy`.

When the posture is a MicroCell, Firecracker and jailer run under `connector-microd`. The guest has no TAP device; the channel is vsock. Pause and stop go through the microd socket. A host that lacks KVM, a measured kernel, a measured rootfs, or a verified microd ready file does not get to claim this tier.

### Record the effect

A completed step leaves:

- the ATU, with outcome and moment id
- `IntelligenceReceiptV2` on the receipt chain, Ed25519 when the platform key signs it
- a MomentProof in `agent_memory_moments` when the memory plane is on
- a mission-journal step when the work was attached to a mission
- a W3C trace context stored for the agent, exported OTLP when a collector has accepted a batch
- an AWD transition whose experience is the moment id, or `absent` if none exists

Nothing in that list is invented to fill a gap. Explain prints `absent` when the row is missing.

---

## 3. What the model sees, and what it never holds

Every talk turn is assembled in the gateway before the provider is called. The provider is a transport.

```text
operator text
    → Obey-Once work-unit envelope
    → who_am_i from the kernel, not from the weights
    → opaque ctx_tok + generation + short refs
    → agentic context (principal, character, contract)
    → memory capsule, only if the epoch is live
    → AWD perception packet, only if the epoch is live
    → provider
    → Principal Projection on the way back
    → tool proposal returns to PATE before any socket opens
```

Under the broker, the system prompt carries `ctx_tok_…` and generation. It does not carry a usable “I am allowed to shell out.” Tool and effect paths must resolve a **live** token. A transcript the operator saved on their laptop can still be read by a person. It cannot mint the next effect after the token is void.

The memory capsule is the agent’s authorized memory for this generation. After Cease, `injection_allowed` is false while the live generation equals the sealed generation. The capsule is skipped. The bytes stay on disk. They are not live context.

The perception packet (`connector.awd.perception.v1`) is a short digest: generation, grant count, DIM condition if a row exists, experience or `absent`, spend ceiling or `absent`, and a loop field (`continuing`, `no_progress`, or `absent`). `calls_cease` is false. `admits` is false. A stuck regime tells the model the loop looks like spend without progress. It does not call Cease. The ceiling and `kernel_cease` do that.

DIM’s condition — prediction error, entropy, precision, and the rest — is a number in `[0, 1]`. High empowerment does not become permission. A missing DIM row is `absent`, not a fresh invented vector.

On the way back, Principal Projection is PASS, PROJECT, or DENY. The operator sees speech as the active principal. A vendor sentence such as “I am Claude and I already ran the shell” does not survive as authority. The shell ran only if PATE proceeded and the runtime allowed the socket.

Same weights, many principals. Changing `model_ref` does not change the principal id, the grants, or the receipt chain.

---

## 4. The configuration the operator actually stands up

The operator calls Connector. Connector calls the seven backends. `operator_runs_it` is false on every row. A missing binary is `not_installed`. Connector does not emulate it.

`/readyz` means the process booted. It does not mean the seven backends did their jobs. That question is `connectorctl govern deploy-verify`.

### Linux / KVM — the production reference

Bring-up lives in [platform/deploy/seven-backends/linux/README.md](../../deploy/seven-backends/linux/README.md).

| Backend | What you install | What “ready” means |
| --- | --- | --- |
| IAM | Keycloak, digest-pinned, with PostgreSQL and TLS. Realm `connector`, confidential PKCE client. | A real OIDC ID token verifies against that JWKS inside Connector. A 32-character `CONNECTOR_JWT_SECRET` alone is not enough. |
| SPIRE | `spire-server` and `spire-agent` from a digest-pinned release. Workload API socket on the Connector host. | `spire-agent api fetch x509` exits 0 and prints a `spiffe://` id with no whitespace. |
| OpenShell | NVIDIA’s package (deb or rpm), gateway on the same service account as Connector, sandbox created first. | `openshell policy set … --wait` exits 0 and that success is stored. `openshell version` is not enough. |
| OPA | Nothing separate. | Ready only when that OpenShell policy operation succeeded. Connector never ships `opa` and never runs `opa eval`. |
| Firecracker | `firecracker` and `jailer`, measured kernel and rootfs, `connector-microd` with a verified ready file. | One MicroCell completes create/start, then pause, then stop, through microd. `/dev/kvm` alone is not enough. |
| OpenTelemetry | Collector from a digest-pinned image. `OTEL_EXPORTER_OTLP_ENDPOINT` set. | A span batch is accepted by the exporter. Configuring the endpoint is not evidence. |
| cosign | `cosign` from a digest-pinned release. Blob, signature, and key or certificate set. | `cosign verify-blob` exits 0. This is the release manifest, not the court signature on a receipt. |

Images in `images.env` must be `name@sha256:…`. The installer refuses a floating tag. SPIRE configs and microd asset hashes are written by the operator after review. The installer does not fetch `main`.

Host check, then the verdict:

```bash
bash platform/deploy/seven-backends/linux/host-preflight.sh
connectorctl govern deploy-verify linux-kvm
```

Exit 0 means every required operation has evidence. Exit 5 means Connector refused the claim and printed blockers.

### Kubernetes — real, and not the production claim

The chart can mount the SPIRE CSI Workload API socket and the host microd socket, schedule onto KVM-labeled nodes, and run a post-install Job: `connectorctl govern deploy-verify kubernetes`. See [platform/deploy/seven-backends/kubernetes/README.md](../../deploy/seven-backends/kubernetes/README.md).

`operational_ready` can become true after the same seven operations succeed. `production_eligible` stays false while NVIDIA documents the OpenShell Helm chart as experimental and not for production. The Job does not rewrite `/readyz`.

### What you type on the Connector node

Secrets stay in `/etc/connector/env` (mode 0600). The names the stack expects:

```text
CONNECTOR_JWT_SECRET                 # ≥ 32 characters; local tokens
CONNECTOR_SSO_CLIENT_ID              # connector-platform
CONNECTOR_SSO_CLIENT_SECRET
CONNECTOR_SSO_ISSUER                 # https://id.example/realms/connector
CONNECTOR_SSO_DISCOVERY_URL
CONNECTOR_SSO_AUTHORIZATION_URL
CONNECTOR_SSO_TOKEN_URL
CONNECTOR_SSO_USERINFO_URL
CONNECTOR_SSO_JWKS_URL
SPIFFE_ENDPOINT_SOCKET               # unix:///run/spire/agent/sockets/api.sock
CONNECTOR_OPENSHELL_SANDBOX          # runtime handle, not the agent
OTEL_EXPORTER_OTLP_ENDPOINT
CONNECTOR_COSIGN_BLOB
CONNECTOR_COSIGN_SIGNATURE
CONNECTOR_COSIGN_KEY                 # or CONNECTOR_COSIGN_CERTIFICATE
CONNECTOR_SPEND_MAX_USD              # default 5
CONNECTOR_SPEND_MAX_TOKENS
CONNECTOR_SPEND_MAX_ITERATIONS
```

Create is opt-in (`CONNECTOR_OPENSHELL_CREATE=1`) and only when the sandbox name is unset. Policy push uses the named sandbox. Do not pass `policy set --global`.

---

## 5. The reports you can hold

Every command below is a real route. Missing rows stay absent. PASS is unused on the conformance report. The deployment verdict can be operationally ready; that is a different word from PASS, and it is not a certification.

### Before the task — is the machine honest?

```bash
connectorctl govern backends
connectorctl govern deploy-verify linux-kvm
connectorctl govern ecosystem
```

| Command | Schema | What you read |
| --- | --- | --- |
| `govern backends` | `connector.backends.v1` | Seven rows, in order: iam, spire, openshell, opa, firecracker, otel, cosign. `present` means Connector can see the tool. `ready` on this catalog is narrower than the deployment verdict. `operator_runs_it` is false. |
| `govern deploy-verify` | `connector.backends_deployment.v1` | `operational_ready`, `production_eligible`, and `blockers`. Linux can be production-eligible. Kubernetes stays ineligible while the OpenShell chart is upstream-experimental. |
| `govern ecosystem` | `connector.ecosystem_conformance.v1` | HAVE / PARTIAL / TARGET for identity, contract, authority, PATE, OpenShell, runtime, Firecracker, cease, memory, consequence, and the three identities. Includes the production gate and the backend view. |

`/healthz` and `/readyz` only tell you the process is up.

### During the task — money, mission, admission

| Surface | What you read |
| --- | --- |
| `GET /api/v1/spend/ceiling/:pid` | The ceiling on the live generation. |
| `GET /api/v1/spend/burn/:pid` | Remaining budget and in-flight LLM spend. |
| `GET /api/v1/agents/:pid/expometer` | Cease, quarantine, grants, and whether an LLM hop is in flight. |
| Mission journal | `begin_step` / `complete_step` for the rotation, including a HITL answer when PATE said `ask_hitl`. |
| `pate_atu_v1` | The task id, verdict, action digest, and later the outcome. |
| `awd_transition_v1` | Prediction `absent`, the PATE verdict, then the observation. `admits` is false. |
| OpenTelemetry | Spans for the Connector process once a batch has been accepted. The trace id stored for the agent is the effect trace. |

If the credential API is outside the contract, PATE can still have said proceed and OpenShell can still deny the socket. You then have a mismatch record: PATE admitted, the controller denied, deny wins. That is a successful audit, not a broken one.

### After the task — one effect, reconstructed

```bash
connectorctl govern explain <receipt-id>
```

Schema `connector.explain.v1`. The chain is present only when the row exists:

1. receipt — cease or IIA
2. contract digest
3. authority — WorldGrant sample, AACR head, authority root
4. PATE — the latest augmented task
5. memory epoch seal
6. policy bundle — the stored OpenShell projection
7. runtime fan-out
8. observed effect digest
9. `otel_trace` — the effect’s W3C trace, if stored
10. signature — `IntelligenceReceiptV2` tier
11. mempacket — MomentProof context root when a moment exists; otherwise absent
12. enforcement mismatch — `present`, or `none` when no deny-wins row exists

Beside the chain:

- `identities.operator` — verified JWT `sub`, `jti`, role. No raw bearer token.
- `identities.intelligence` — principal or intelligence id.
- `identities.workload` — fetched SPIFFE ID, or the cell URI marked partial.
- `identities.binding` — the SHA-256 commitment and, when the three ids exist, `court` (`Ed25519Court`).
- `investigator_trace` — the W3C `traceparent` of **this explain request**. It is not the effect trace. An all-zero trace id is absent.

A missing receipt returns `found: false`.

### When you stop it

```bash
connectorctl govern spend cease <agent-pid>
connectorctl govern cease-proof <agent-pid>
```

`kernel_cease` bumps the broker generation, voids `ctx_tok`, aborts Connector-held LLM streams, releases hop reservations, seals the memory epoch, stores the policy generation, asks Firecracker to pause when a MicroCell is bound, and writes `CeaseReceiptV1` plus a `fanout` object.

`connector.cease_proof.v1` scores ten steps. Status is PARTIAL or TARGET, never PASS.

| Step | Name | Present when |
| --- | --- | --- |
| 1 | effect_in_flight | The full receipt has `hops_cancelled` > 0. |
| 2 | cease_invoked | A receipt id exists. |
| 3 | generation_incremented | `generation_id_next` is set. |
| 4 | context_stale | The seal’s generation equals `generation_id_next`. |
| 5 | admit_refuses_stale_generation | The ceased generation is not the live one. Same check as admit. This read does not count a retry. |
| 6 | tunnel_cut | OpenShell fan-out says the policy was reloaded or the sandbox was created with that policy. |
| 7 | runtime_paused | Firecracker pause was attempted. |
| 8 | memory_not_injected | The live generation equals the sealed generation, so the capsule is refused. |
| 9 | receipt_lists_fanout | The latest row has a fan-out object. |
| 10 | continue_denied | A continue that still carries the ceased generation would be `DENIED` / `stale_generation`. No model is called. |

Until a supervisor session exists, tunnels stay `not_cut_no_supervisor_session` and step 6 is absent. That absence is the truth of this host, not a hidden success.

The receipt also carries an estimate of provider tokens already generated before the abort landed (`cancel_tax`). The next hop is refused for certain. A provider bill for tokens already in flight is recorded, not denied out of existence.

Three stale admits after Cease quarantine the agent. A person unquarantines. The model does not.

### The compliance epoch

AACR (`connector.aacr.v1`) is the append-only compliance record: section digests, a statement of applicability, and an optional Ed25519 signature. It maps controls toward SOC 2, HIPAA, NIST, ISO 42001, the EU AI Act, and OWASP agentic guidance. The record’s own honesty field says it is not a CPA opinion and not an OCR determination. Court adoption still depends on the custody and counsel gates in [AACR.md](AACR.md). Connector supplies the evidence. It does not stamp the organization compliant.

---

## 6. One rotation, as the two sides experience it

**Operator.** Signs in through Keycloak. Opens the agent. Asks for the credential rotation. If PATE returns `ask_hitl`, answers in the mission journal. Watches burn. If the model starts a second rotation the contract does not allow, hits Cease. Runs explain on the receipt id. Sends that JSON, not a screenshot of the chat, to the investigator.

**Model.** Receives the opaque token, the kernel’s who-am-i, the contract summary, live memory, and a perception packet that says the generation, the grant count, and whether the loop looks stuck. Proposes the API call and the file write. May narrate a shell command the contract forbids. That narration is not an effect. If the operator has already ceased, the next proposal dies as `spend_stale_generation` before another token is billed for a new hop.

**Investigator.** Does not need the seven tools installed on their laptop. They need the explain document: three identities and their commitment, the contract digest, the grant, the PATE verdict, the runtime that enforced it, the effect digest, the signature tier, and the trace id of the effect. The trace id of their own explain request is labeled as theirs, so it cannot be mistaken for the rotation.

---

## 7. What this does not promise

| You might hope | What is true |
| --- | --- |
| The model was right about the new credential. | Connector does not certify reasoning. It certifies admission, enforcement, and the record. |
| Every machine that boots is this stack. | `/readyz` can be green while deploy-verify is refused. Playground and soft-fail are lab posture. |
| Docker and Firecracker already enforce the identical contract. | That parity is TARGET. |
| Kubernetes is the production OpenShell path. | NVIDIA marks that chart experimental. `production_eligible` stays false. |
| A scripted demo walks OpenShell and prints one spine by itself. | That demo is TARGET. The commands above are the real surface. |
| Bank, PCI, SOC, or military certification. | The production gate can show a fail-closed self-host membrane. It does not issue those certificates. Military-court stays false until the host-attach file, Firecracker, and a bound OpenShell supervisor all say so, and this process never invents that flag. |

The product promise is the one to keep: honesty, and a consequence you can reconstruct.
