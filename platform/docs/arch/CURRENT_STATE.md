# Current state — what exists, and what it can do

**Status:** Reality as of this tree. This is not the intended end state in [GOVERNED_CRITICAL_AGENT.md](GOVERNED_CRITICAL_AGENT.md). That file describes the path. This file says which parts of that path run today.

A developer machine that has not installed Keycloak, SPIRE, OpenShell, Firecracker, a collector, and cosign will boot Connector and then **refuse** `govern deploy-verify`. That refusal is the product working. It is not a finished seven-backend deployment.

---

## What you can do on a machine with only Connector

These paths are in the `connector-platform` binary. They do not need the seven upstreams.

| You can | What actually happens |
| --- | --- |
| Register an agent | `IntelligencePrincipalV2` and `AgentIdentityEnvelopeV2` are minted. The intelligence id is Connector’s. It is not the model name. |
| Compile a contract | `AgentContractV2` gets a digest, deny-default network, and denied operations. The OpenShell YAML projection is produced in schema version 1. Pushing it is a separate step and does nothing useful until `openshell` exists. |
| Issue and list grants | WorldGrant, attenuation, and tombstones are stored. Experience and the world-dynamics view cannot create or widen a grant. |
| Admit or refuse an action | PATE writes an Augmented Task Unit. Verdicts are proceed, ask, defer, quarantine, or block. A prediction does not override that verdict. |
| Talk to an LLM through Connector | The gateway injects kernel identity, an opaque context token when the broker is on, and memory only while the generation is live. The provider is replaceable. Chat text is not a grant. |
| Stop an agent | `kernel_cease` bumps the broker generation, voids the context token, aborts Connector-held streams, releases spend reservations, seals the memory epoch, and writes `CeaseReceiptV1`. |
| Prove the stop | `govern cease-proof` scores ten steps from stored records and `generation_is_live`. It does not call a model. Status is PARTIAL or TARGET, never PASS. Step 10 is present only when a continue of the ceased generation would be `DENIED` / `stale_generation`. |
| Reconstruct one receipt | `govern explain` walks whatever rows exist: contract, grants, PATE, memory seal, projection, fan-out, effect digest, trace, signature. Missing rows are `absent`. |
| Sign the three names | When explain has a verified JWT subject, a fetched SPIFFE ID, and an intelligence id, it stores a SHA-256 commitment and an Ed25519 `SignedPayloadV2`. `authorizes` is false. Without a fetched SPIFFE ID, there is no court signature. A cell URI does not count. |
| Read condition, not permission | DIM stores a condition in `[0, 1]`. Agentic World Dynamics V0 reads it, plus principal, generation, grant count, and spend ceiling. Prediction stays `absent`. The packet is omitted when the memory epoch is sealed. |
| See an honest report | `govern ecosystem` prints HAVE, PARTIAL, or TARGET. The unit tests lock that OpenShell and explain are never marked PASS. |
| Log in | Local JWT (HMAC-SHA256) works when `CONNECTOR_JWT_SECRET` is at least 32 characters. OIDC against Okta, Google, Azure AD, GitHub, or any issuer — including Keycloak — is implemented. A Keycloak login becomes deployment evidence only after a real JWKS-verified ID token. |

Spend ceilings default to about $5, 200,000 tokens, and 32 iterations per generation unless the environment overrides them. Over budget, the next admit is refused. That is real on this process.

---

## What is real only when the upstream binary is installed

The code calls the real program. It does not emulate a missing one. On a host where the binary is absent, the row is `not_installed` and deploy-verify stays refused.

| Upstream | What Connector will do if it is installed | What this tree has not done |
| --- | --- | --- |
| NVIDIA OpenShell | `openshell --version`, `policy set --wait`, optional `sandbox create --policy -- sleep 20`, `logs --source sandbox`. A policy push that exits 0 is stored. A log line counts as OPA only when it says `denied` and `by policy`. `true` exits before the supervisor relay, so create does not use it. | On this host, `policy set --wait` exited 0 against sandbox `prophetic-coonhound` and that row is stored. Catalog `ready` still stays false until that stored push exists. |
| OPA | Nothing of its own. Readiness follows that OpenShell policy success. Connector never runs `opa eval`. | No separate OPA process, on purpose. |
| SPIRE | `spire-agent api fetch x509` when `SPIFFE_ENDPOINT_SOCKET` is set. The id is kept only if the process exits 0 and prints `spiffe://`. The v1.15 join token belongs in the agent body, not in plugin data. A used join token cannot re-attest; a new token is required after the agent drops its SVID. | Connector does not issue SVIDs. This platform process fetched `spiffe://connector.local/connector`. |
| Firecracker + jailer | Probe KVM, kernel, rootfs, and jailer. `connector-microd` can create, start, pause, and stop a MicroCell. Deploy-verify wants that full sequence on one cell, plus a verified microd ready file. Firecracker v1.9 pauses with `PATCH /vm`, not `PUT /vm`. | On this host, microd is verified and one MicroCell (`mc-d-7ee2e73ebeed`) was created, paused, and stopped through Connector. That sequence is the store row. The KVM acceptance job by itself does not write it. |
| OpenTelemetry | If `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans export OTLP. Deploy-verify turns ready only after this process's exporter sees an accepted batch. A restart clears that bit until the next accepted export. | This process exported a batch the collector accepted. A direct POST to the collector still does not count. |
| cosign | `cosign verify-blob` when blob and signature paths are set. `verified` is the exit code. | This platform process verified the configured blob. `verified` is still the CLI exit code, not a release certificate. |
| Keycloak | The existing OIDC client can use Keycloak’s authorize, token, userinfo, and JWKS URLs. A successful ID-token check records IAM evidence. The container filesystem must be writable because `start` rebuilds the server image. A password-grant user needs email, first name, and last name or Keycloak returns `Account is not fully set up`. `/auth/sso/login` and `/auth/sso/callback` are public. A self-signed lab certificate is accepted only when `CONNECTOR_SSO_INSECURE_TLS=1` and the process is not in a production posture. | The SSO callback on this host verified a Keycloak ID token and wrote the IAM row. The cargo test does not write that row. |

---

## What was added, and what it is

These files are in the tree. They are installers, gates, and reports. They are not a running production stack.

| Piece | Reality |
| --- | --- |
| `connectorctl govern backends` | Lists the seven tools. `operator_runs_it` is false. Presence is not readiness. |
| `connectorctl govern deploy-verify linux-kvm` | Fail-closed. Exit 0 only when all seven operations have evidence. On an unprovisioned machine it exits refused and prints blockers. |
| `govern deploy-verify kubernetes` | Same seven operations. `production_eligible` stays false because NVIDIA documents the OpenShell Helm chart as experimental. |
| `platform/deploy/seven-backends/linux/` | Digest-pinned compose for Keycloak, PostgreSQL, and an OpenTelemetry collector; systemd units for SPIRE; an installer that checks SHA-256 before copying binaries. It refuses floating image tags. It does not download `latest`. |
| `platform/deploy/seven-backends/kubernetes/` | Values and a post-install Job that calls deploy-verify. Helm lint passed. The chart was not installed onto a cluster from this workspace. |
| `.github/workflows/seven-backends-gate.yml` | Runs the verifier unit tests and shell syntax on GitHub. The live seven-backend job runs only on a self-hosted KVM runner when someone dispatches it. |
| Tests | `deployment_verify` : 6 passed. Ecosystem explain/cease tests: 11 passed. They lock the rules. They do not prove a live supervisor. |

---

## What a real operator gets today, in practice

**On a laptop or CI runner without the seven tools.** A governed agent runtime: identity, contract, grants, PATE, spend limits, Cease, explain, and an ecosystem report that says what is still partial. Isolation falls through to whatever cage is actually configured (subprocess lab is explicitly weaker). OpenShell, SPIRE, Firecracker, and cosign show up as missing or not ready. That is a true report.

**On a Linux host after the upstreams are installed and the evidence exists.** The same commands, plus a deploy-verify that can exit 0. Then a contract can be pushed into a real OpenShell sandbox, a SPIRE SVID can appear on explain, a MicroCell can be paused on Cease, an OTLP batch can count, and a cosign check can count. Until those commands have succeeded once, the verdict stays refused. The software will not mark them ready in advance.

**What you still cannot claim, on any machine, from this tree.**

- The same contract is enforced identically on Docker and on Firecracker. That is TARGET.
- A script that drives OpenShell and prints one spine by itself. The commands exist. The scripted public demo does not.
- Kubernetes as the production OpenShell path.
- A bank, PCI, SOC, or military certificate. The production gate can describe a fail-closed self-host membrane. Military-court stays false until a host-attach file, a ready Firecracker probe, and a bound OpenShell supervisor all say so. This process does not set that flag.
- That the model’s answer was correct.

---

## Product install

`connectorctl product` is the operator lifecycle for one path, Linux with KVM. `product install <spec>` dry-runs. `connectorctl --yes product install <spec>` as root verifies pinned digests, writes SPIRE and service config, starts Keycloak, the collector, SPIRE, and microd, and enables a reconcile timer. Secrets are files under the state directory, mode `0600`. Inline passwords and unpinned images are refused.

`product status` prints the board. A row is `READY` only when that process is up and deploy-verify has evidence. A dead collector does not stay `READY` because an earlier batch succeeded. The board sees a live SPIRE server and agent, a Keycloak realm on localhost, an OpenShell gateway listening on port 17670, and a microd ready file. It does not treat `openshell version` as proof: that subcommand does not exist; the CLI flag is `--version`. `product reconcile` restarts SPIRE and microd at most three times, then stops. `product demo governed-agent` refuses while the scripted spine is incomplete and does not register an agent to hide that. `product task` can register an agent, patch its model and surface contract, and score the twelve outcomes. Its exit is success only at `executed`, `reconstructed`, or `ceased`. A configured or merely admitted agent stays refused. A completed PATE task now keeps one spine on that `task_id`: a mutating effect needs an idempotency key and one execution, spend commits only when the verdict is proceed and the effect was observed, and the spine `admits` stays false. A denied or unobserved completion releases the reservation. Paths that skip this completion are still open.

A live run on this host (2026-10-02) got checksum-pinned cosign, SPIRE, the collector, Keycloak, and OpenShell to exit 0. That artifact is `artifacts/five-backends/five-backends.json`. It does not set `operational_ready` by itself.

On 2026-10-03 the same host's `product status` printed `CONNECTOR READY`: 7/7 evidence, `production_ready` true, and `deploy-verify` `operational_ready` true for `linux-kvm`. That board was the live processes plus the SSO callback, the stored OpenShell policy set, the Firecracker create/pause/stop on one MicroCell, an exporter-accepted OTLP batch, and cosign in that process. Killing any of those processes makes the matching row `NOT READY` on the next status. Kubernetes `production_eligible` stays false.

Kubernetes is not this installer. The command does not download `latest`. On a machine without the pinned artifacts and `/dev/kvm`, install refuses and names the blocker.

## Effect inventory

Paths that admit through PATE before an effect: host MCP dispatch, MCP `memory_write`, `agent_register`, and `agent_signal`, the microVM tool plane after a proceed ticket, API v2 tool invoke, a workflow step that names `bridge:tool`, A2A channel send, multiagent and experiment talk, and a compensation inverse named `bridge:tool`. Inbound CNP actuation without a PATE task id is refused. A missing or non-proceed verdict does not execute. `allow_narrow` stays a non-mutating transport observation. `product task` now posts one server job that stores the confirmed model, the surface contract, and one ask-only grant.

Still open, so inventory completeness is false: protocol completions that do not share one task id, native invocation without a tool binding, and any route not in the list above. Break-glass flags void the inventory until those paths are rechecked. A live production run of this inventory has not been recorded.

## Short version

Connector today is a real control plane for agent identity, admission, spend, cease, and reconstruction, plus a Linux/KVM installer that configures the seven upstreams and then tells the truth. It can call OpenShell, SPIRE, Firecracker, OpenTelemetry, and cosign when those programs are on the host. It cannot, and does not, pretend they ran. On this host, `product status` said `CONNECTOR READY`. That headline is the live board, not a certificate, and it does not survive a dead process.
