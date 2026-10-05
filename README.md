<p align="center">
  <a href="https://cnktros.com"><img src="oss/assets/cnktros-logo.png" alt="cnktros" width="120"></a>
</p>

<h1 align="center">Connector</h1>

<p align="center">
  <strong>Govern an agent before its intention becomes a consequence.</strong><br>
  Identity, authority, admission, proof, and a way to stop.
</p>

<p align="center">
  <a href="https://cnktros.com"><strong>cnktros.com</strong></a>
</p>

<p align="center">
  <img src="oss/assets/architecture.png" alt="Connector OS on cnktros.com. One governed workspace: principal, purpose, presence, knowledge, directives, authority, situation. PATE admits an effect. Runtime may still deny it. agentgateway is a target, not integrated." width="920">
</p>

<p align="center">
  <code>./up.sh</code> &nbsp;→&nbsp; <a href="http://127.0.0.1:9091/">127.0.0.1:9091</a>
</p>

Connector does not replace your model. It decides whether one exact effect may happen, records what did, and can revoke the authority to do it again.

| | |
| --- | --- |
| **Admit** | PATE returns Proceed, Ask, Defer, Quarantine, or Block. Ask stays open for a person. |
| **Bring an agent** | Paste Connector’s MCP handle into a client, or paste that agent’s MCP, A2A, or chat URL here. A link is not a grant. |
| **Stop** | Cease fences that generation. Old authorization does not keep working. |

## Start

Linux, with Rust, Cargo, Docker, curl, Node.js, and [Trunk](https://trunkrs.dev/).

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk
./up.sh
```

Open <http://127.0.0.1:9091/>. Local login is `Authorization: Bearer dev-token`. Keep that token on your own machine.

On **Run**, open **Demo**. On **Bring your agent**, connect something you already use. When PATE says **Ask**, decide that digest on **Fix**. **Watch** shows the evidence.

A smaller library server, without the operator UI: [docs/quickstart.md](oss/docs/quickstart.md).

## Honest status

**HAVE** a local node: workspace, contracts, PATE, receipts, Cease. **PARTIAL** wiring to Keycloak, SPIRE, OpenShell, OPA, Firecracker, OpenTelemetry, and cosign. **TARGET** for agentgateway forwarding and production coverage.

`./up.sh` does not download Firecracker or OpenShell. A running box is not an installed backend on another host. A receipt is not proof the model was right. Nothing here means secure, correct, safe, compliant, or production-ready.

## License

Libraries under `oss/` are [Apache License 2.0](oss/LICENSE). The node under `platform/` is [Business Source License 1.1](platform/LICENSE). Report exploitable findings privately through [SECURITY.md](oss/SECURITY.md).
