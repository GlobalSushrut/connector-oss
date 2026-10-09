# Third-party plugin publish runbook (P2.2)

## Prerequisites

- `connectorctl` and `connector-platform` built (`make platform-build`)
- Hub URL: `CONNECTOR_HUB_URL` or local `platform/hub`
- Ed25519 signing key for `.cpkg` (see `platform/cpkg`)

## Steps

1. **Author** AGOS plugin with `cargo connector new my-plugin` (see `docs/agos/plugin-authoring.md`).
2. **Verify locally:** `connectorctl plugin verify ./my-plugin` (MVP checks manifest + handshake).
3. **Pack:** `connectorctl plugin pack ./my-plugin -o dist/my-plugin.cpkg`
4. **Publish:** `connectorctl hub publish dist/my-plugin.cpkg` (requires hub credentials).
5. **Install on node:** Dashboard **Apps → Install** or `connectorctl plugin install <id>`.

## v1 limits

Full **2A.9** certification and three live community plugins are tracked in [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).
