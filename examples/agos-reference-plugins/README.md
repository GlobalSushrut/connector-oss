# AGOS reference plugins (Phase 6.7)

In-repo **third-party-style** examples for Connector Hub naming: **`acme/slack-notifier`**, **`acme/jira-bridge`**, **`acme/datadog-forwarder`**.

Each crate depends **only** on **`agos-sdk`** (public manifest + ABI helpers). They are **stubs**: load `plugin.toml`, assert **`agos_abi`**, print a one-line banner — no live Slack/Jira/Datadog traffic.

## Verify

From the repository root:

```bash
for d in examples/agos-reference-plugins/acme-*; do
  (cd "$d" && cargo build --release -q && connectorctl plugin verify .)
done
```

## Publish (later)

Package as **`.cpkg`**, sign, and publish via Connector Hub when your registry is configured. These trees are starting points, not published artifacts.

See **`docs/agos/plugin-authoring.md`**.
