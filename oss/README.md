# Connector

## The consequence control plane for autonomous AI

> **Govern AI before intelligence becomes consequence.**

**Identity. Authority. Admission. Runtime. Proof. Cease.**

Models no longer only answer. Agents write files, run code, call APIs, hold credentials, invoke MCP tools, talk to other agents, deploy software, trigger workflows, spend resources, and keep going. The industry is getting very good at making them capable.

Connector is for the question that follows capability:

> **When an agent can act, what governs the moment its intention becomes a real consequence?**

**One sentence.** Connector binds an intelligence's identity, purpose, and authority to one exact effect, admits that effect through PATE, executes it only when permitted, records what happened, and can revoke the authority to do it again.

**Six words.** Identity → Authority → Effect → Proof → Cease

---

## The boundary

Saying "rotate the production credential" is information. Rotating it is an effect. Suggesting a refund is information. Issuing it is an effect. Proposing a deploy is information. Changing production is an effect.

```text
REASONING          free to propose
    │
INTENTION
════════════════════════════
    CONNECTOR BOUNDARY
════════════════════════════
    │
ADMISSION → EXECUTION → CONSEQUENCE
```

Connector does not decide what a model should think. It governs what intelligence is allowed to turn into consequence. A prompt cannot answer that. It takes infrastructure.

## The chain

```text
WHO is acting?
WHY does this intelligence exist?
WHAT authority does it hold right now?
WHAT exact effect is requested?
SHOULD it happen — Proceed, Ask, Defer, Quarantine, or Block?
WHERE does it execute?
WHAT actually happened?
CAN the chain be reconstructed?
CAN future authority be killed?
```

```text
IDENTITY → PURPOSE → AUTHORITY → EXACT EFFECT → PATE
    → RUNTIME → ATTEMPT → OBSERVATION → RECEIPT
    → CONSEQUENCE → CEASE
```

Seeing a tool is not permission to run it. Connecting an agent is not trust. Knowledge is not a directive. A directive is not a grant. Memory is not authority.

## PATE

PATE is the only admission authority. One requested effect, one verdict:

| Verdict | What happens |
| --- | --- |
| **Proceed** | That exact effect may enter the governed runtime. |
| **Ask** | A person must decide. The task stays open. The handler does not run. |
| **Defer** | The request is not ready to execute. |
| **Quarantine** | The intelligence or task is held in a restricted posture. |
| **Block** | The effect does not execute. |

No Connector-managed consequence should happen merely because an agent asked for it.

## Seven dimensions

An agent is not a prompt plus a model name.

| Dimension | Question |
| --- | --- |
| **Principal** | Who is this intelligence? |
| **Purpose** | Why was it created? |
| **Presence** | Where and how is it operating? |
| **Knowledge** | What information may support its reasoning? |
| **Directives** | What instructions govern its behavior? |
| **Authority** | What consequences may it create? |
| **Situation** | What is happening now? |

Two copies of the same model can exist for different purposes and must not inherit each other's authority. Files, ingested knowledge, memory, mutable state, and the context actually sent to a model stay separate. Upload is not model context.

## Bring the intelligence you already have

Connector does not replace your model, framework, or MCP server. It puts a governance envelope around consequence.

```text
your agent, editor, gateway, or future client
                 │
                 ▼
             Connector
                 │
     reachability is not authority
                 │
      API · tool · file · workflow · agent
```

Two directions cover the market, including products that do not exist yet:

- **They call Connector.** Any MCP client — an editor, a desktop app, a gateway — pastes this node's MCP handle into its own config. A stdio command is their transport, not a URL Connector probes. Adding the address does not grant them.
- **Connector calls them.** Paste the HTTP MCP server, A2A card (`/.well-known/agent.json`), or OpenAI-compatible `/v1` chat URL they already publish. Hosted chat APIs need a key. The link is model-only until a contract, grant, and PATE route exist.

A chat window with none of those addresses stays unconnected. There is no integration per logo.

## The stack Connector joins

Connector does not rebuild identity, policy, isolation, tracing, or signing. It binds those decisions to the same intelligence, the same authority, the same admitted effect, and the same consequence.

| System | Primary job | Where it sits |
| --- | --- | --- |
| **Connector** | Intelligence → consequence | The joining layer |
| **Keycloak** | Operator identity | Identity |
| **SPIFFE / SPIRE** | Workload identity | Identity |
| **NVIDIA OpenShell** | Agent runtime boundaries | Execution |
| **OPA** | Policy decisions | Inside OpenShell |
| **Firecracker** | MicroVM isolation | Execution |
| **agentgateway** | MCP, A2A, model, and service traffic | Proposed traffic plane |
| **OpenTelemetry** | What the system observed | Evidence |
| **Sigstore / cosign** | Artifact provenance | Evidence |

```text
OpenShell:     what may this runtime touch?
OPA:           does this input satisfy policy?
SPIRE:         which workload is this?
agentgateway:  how is this traffic routed?
OpenTelemetry: what was observed?
Frameworks:    how should the agent reason and continue?

Connector:     which intelligence, under which purpose and authority,
               may create this exact consequence, through which runtime,
               what happened, and does that authority still exist?
```

A healthy backend does not prove an effect was admitted. An admitted effect does not prove the deployment is production-ready.

## Proof, and stop

Logs say something happened near a timestamp. Connector aims at one chain: intelligence, request, authority, admission, attempt, observed effect, receipt, trace, consequence.

**Cease** is how stop becomes real. When a budget ends, a credential is revoked, a contract changes, or an operator stops an agent, that generation is fenced. Old authorization does not keep working. The model may still be able to think. Capability is not authority.

## One effect, end to end

An operations agent wants to rotate one database credential.

```text
Agent proposes "rotate credential"
        │
identity + purpose + contract
        │
exact operation, exact target, exact generation
        │
PATE ── Ask ──► a person, on the exact digest
     ├─ Block ─► no execution
     └─ Proceed
            │
     governed runtime
            │
     observed result → receipt → evidence
```

Afterward the operable questions are: who rotated it, why that intelligence existed, which grant allowed it, which target was admitted, whether a person approved that digest, which policy version was active, whether execution happened, which receipt represents it, and whether that authority can be reused.

## What is already here

This tree already contains principals, the seven-dimension workspace, contracts and grants, PATE, execution attempts, receipts and traces, separated memory and state, Cease, and a universal connection surface. The local node can be started and explored.

Status stays in three words: **HAVE**, **PARTIAL**, **TARGET**. A local start is not production. A box in the architecture is not an installed backend. A policy decision is not proof the outside effect occurred. A receipt is not proof the model was right. A sandbox is not proof of total security.

Three claims stay independent:

| Claim | Means |
| --- | --- |
| `inventory_complete` | This build's declared mutations are classified as governed or explicitly non-effecting. |
| `effect_mediated` | One named effect has evidence that it traversed the required path. |
| `production_ready` | The production infrastructure and operational evidence for that claim are live. |

None of them means secure, correct, safe, or compliant. Firecracker and OpenShell are not downloaded by `./up.sh`. If they are absent, they stay absent. agentgateway stays a target until forwarding acceptance passes. Missing evidence stays missing.

## Start

Linux. Install Rust, Cargo, Docker, curl, Node.js, and [Trunk](https://trunkrs.dev/).

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk
```

From the repository root:

```bash
./up.sh
```

That one command reads `oss/boot.defaults`, prepares or probes the configured industry tools, builds the operator UI and `connector-platform` when a fresh clone does not have them, starts the API and workspace, waits until health responds, and prints the URL.

Open <http://127.0.0.1:9091/>.

Local development login:

```text
Authorization: Bearer dev-token
```

Keep that token and this default configuration on your own machine. Do not put them on an untrusted network.

Change ports before the next boot in `oss/boot.defaults`:

```bash
CONNECTOR_PORT=9091
KEYCLOAK_HTTPS_PORT=18443
OTEL_HEALTH_URL=http://127.0.0.1:13133
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
SPIRE_BIND_PORT=18081
AGENTGATEWAY_PORT=4000
```

Provider keys, signing keys, and production JWT secrets stay out of git.

## Use it

1. Open **Run** and select **Demo**. Demo already knows what Connector is, how a turn is admitted, and who is building it.
2. Choose **Start talking**. Connect a provider key, or a local OpenAI-compatible endpoint, before expecting free-text answers.
3. Open **Workspace** and read Principal, Purpose, Presence, Knowledge, Directives, Authority, and Situation. Absent means absent.
4. Open **Bring your agent**. Either paste Connector's MCP handle into the client you already use, or paste that product's MCP, A2A, or chat URL. Reading an address does not grant it.
5. When PATE returns **Ask**, open **Fix**, approve or deny that exact digest, and let the task finish. Done closes the receipt. The decision is what clears the ask.
6. Open **Watch** for outcomes and evidence.

Give a new agent a specific purpose. "General-purpose" is refused. Then grant only the effects it should be able to cause.

## What you get

A place to see who an intelligence is, why it exists, what it knows, what it was told, what it may change, and what it is doing now. A gate before consequence. A human decision bound to one digest. A receipt when a governed effect is observed. A way to cease future authority. An honest empty state when a backend, grant, or proof is missing.

## What an agent gets

A persistent principal, a purpose, a contract, and grants that are explicit. Knowledge that is not secretly permission. A runtime path for the effects it is allowed to cause. An Ask when a person must decide. A stop that removes the ability to create the next governed effect, rather than a sentence asking it to behave.

## Libraries

From `oss/`:

```bash
make rust
cd connector && cargo run -p connector-server
```

`connector-server` listens on `127.0.0.1:8080` unless `CONNECTOR_ADDR` is set. Details are in [docs/quickstart.md](docs/quickstart.md). `./up.sh` is the product path: it runs `connector-platform` and the operator UI.

| Path | Role |
| --- | --- |
| `oss/vac/` | Memory kernel |
| `oss/aapi/` | Action API |
| `oss/connector/` | Engine, trust records, protocols, CLI |
| `oss/sdks/` | Python and TypeScript clients |
| `platform/server/` | The node |
| `platform/ui-leptos/dashboard/` | Operator UI |
| `agos-abi/`, `agos-sdk/` | Build dependencies of the node |

The license server, billing portal, and vendor admin UI are not in the public tree.

## License

Libraries in this directory are [Apache License 2.0](LICENSE). The node under `../platform/` is [Business Source License 1.1](../platform/LICENSE). Report exploitable findings privately through [SECURITY.md](SECURITY.md).

---

**Agent frameworks make agents capable. Runtimes contain them. Gateways connect them. Policy engines decide rules. Observability makes them visible. Connector makes consequences governable.**
