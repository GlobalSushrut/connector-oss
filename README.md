<p align="center">
  <a href="https://cnktros.com"><img src="oss/assets/cnktros-logo.png" alt="cnktros" width="96"></a>
</p>

<h1 align="center">Connector</h1>

<p align="center">
  <a href="https://cnktros.com">cnktros.com</a>
</p>

**What it is.** Connector governs an agent before its intention becomes a real consequence.

**Why we need it.** Agents already write, call tools, spend, and continue. A prompt cannot admit one effect, record it, and revoke the next.

**Today's stack vs Connector.** Frameworks make agents capable. Gateways connect them. Policy judges rules. Logs show activity. Connector binds who acts, what they may cause, and whether that one effect may happen. Teams running agents that change real systems need it.

<p align="center">
  <img src="oss/assets/architecture.png" alt="Connector OS. Identity, purpose, and authority pass through PATE before a consequence. agentgateway is still a target." width="880">
</p>

## Start

The code is this repository: [github.com/GlobalSushrut/connector-oss](https://github.com/GlobalSushrut/connector-oss).

```bash
git clone https://github.com/GlobalSushrut/connector-oss.git
cd connector-oss
./up.sh
```

Open <http://127.0.0.1:9091/>. On that screen choose **Open on this machine**. That is the local dev-token, and it stays on your computer. A portal API key is for a hosted node, not this one.

On **Run**, open **Demo**. On **Bring your agent**, connect something you already use. When PATE says **Ask**, decide that digest on **Fix**. **Watch** shows the evidence.

Needs Linux, Rust, Docker, Node.js, and [Trunk](https://trunkrs.dev/) (`rustup target add wasm32-unknown-unknown`). A smaller library server, without the operator UI: [docs/quickstart.md](oss/docs/quickstart.md).

**Here:** workspace, PATE, receipts, Cease. **Partial:** Keycloak, SPIRE, OpenShell, OPA, Firecracker, OpenTelemetry, cosign. **Target:** agentgateway and production coverage. `./up.sh` does not download Firecracker or OpenShell. This is not a claim of secure, correct, safe, compliant, or production-ready.

Libraries under `oss/` are [Apache License 2.0](oss/LICENSE). The node under `platform/` is [Business Source License 1.1](platform/LICENSE). Report exploitable findings privately through [SECURITY.md](oss/SECURITY.md).
