# Quickstart

From the repository root, after `make rust`:

```bash
cd connector
cargo run -p connector-server
```

In another shell:

```bash
curl -sS http://127.0.0.1:8080/health
```

A healthy process returns JSON from that path. The CLI talks to the same address:

```bash
cargo run -p connector-cli -- doctor
```

Set `CONNECTOR_API_URL` when the server is not on `http://127.0.0.1:8080`.

To scaffold a local project directory:

```bash
cargo run -p connector-cli -- init --quickstart
```

Provider keys stay in the environment. This quickstart does not call a model.
