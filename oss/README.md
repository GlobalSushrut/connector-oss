<p align="center">
  <a href="https://cnktros.com"><img src="assets/cnktros-logo.png" alt="cnktros" width="96"></a>
</p>

<h1 align="center">Connector</h1>

<p align="center">
  <strong>Govern an agent before its intention becomes a consequence.</strong><br>
  <a href="https://cnktros.com">cnktros.com</a>
</p>

<p align="center">
  <img src="assets/architecture.png" alt="Connector OS. Identity, purpose, and authority pass through PATE before a consequence. agentgateway is still a target." width="880">
</p>

## Start

```bash
./up.sh
```

Open <http://127.0.0.1:9091/>. Local login: `Authorization: Bearer dev-token` on your own machine.

Needs Linux, Rust, Docker, Node.js, and [Trunk](https://trunkrs.dev/) (`rustup target add wasm32-unknown-unknown`). Library-only server: [docs/quickstart.md](docs/quickstart.md).

**Here:** workspace, PATE, receipts, Cease. **Partial:** Keycloak, SPIRE, OpenShell, OPA, Firecracker, OpenTelemetry, cosign. **Target:** agentgateway and production coverage. `./up.sh` does not download Firecracker or OpenShell. This is not a claim of secure, correct, safe, compliant, or production-ready.

Libraries under `oss/` are [Apache License 2.0](LICENSE). The node under `platform/` is [Business Source License 1.1](../platform/LICENSE). Report exploitable findings privately through [SECURITY.md](SECURITY.md).
