# DevGuard first run

DevGuard governs **one workstation** (Cursor, Windsurf, Claude Code, etc.). The Connector kernel stores a **local profile**; an optional **management URL** proxies extension status.

## Quick path

1. Start the node: `connectorctl node start`
2. On first boot, the kernel seeds a default local profile when DevGuard is enabled.
3. Open **Plugins → DevGuard**. A saved local profile is onboarding configuration only; it does not make DevGuard healthy or enforced.
4. Bind a repository, attach an agent, install the supported tool hooks, and verify a deny probe. External status is healthy only when the configured workstation status API is reachable.

## Configure from the dashboard

1. **Plugins → DevGuard → Setup**
2. Set primary tool, roles, and tool access (`allow` / `block` / `neutral`)
3. Acknowledge **single workstation** and save

API: `POST /api/v1/plugins/devguard/local-profile` (see OpenAPI / `connectorctl` HTTP helpers).

## External status API (optional)

For a running DevGuard `status-api` on the host:

```bash
export CONNECTOR_DEVGUARD_MANAGEMENT_URL=http://127.0.0.1:<port>
```

The platform proxies `GET /api/v1/plugins/devguard/extension/status`.

## GitHub exact-head evaluation (local)

```bash
# Evaluate a claimed commit SHA against the bound policy on this node.
# Does not publish a GitHub Check Run until a GitHub App with checks:write exists.
curl -sS -X POST "$CONNECTOR/api/v1/devguard/github/checks/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo_id":"acme-checkout","head_sha":"<40-char-sha>","agent_pid":"<pid>"}'
```

`GET /api/v1/devguard/github/status` reports App publish capability honestly (`check_runs_publish: false` today).

## Policy lineage dev ↔ prod

- **Dev:** edit profile in dashboard; export policy YAML from DevGuard CLI on the workstation.
- **Prod:** same profile shape; tighten `block` modes before promoting roles.

See [`PLUGIN_CONTRACT.md`](../PLUGIN_CONTRACT.md) and `plugins/devguard/` workflows.

## Point the coding tool at Connector (required)

DevGuard connect / session start / attach returns `openai_base_url` and `anthropic_base_url`. Set them on the workstation:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9091/v1
export OPENAI_API_KEY=cg_....
export ANTHROPIC_BASE_URL=http://127.0.0.1:9091/v1
export ANTHROPIC_API_KEY=cg_....
```

Connecting a tool also engages the **LLM vendor cut**: TCP 80/443 to Anthropic/OpenAI/etc is DROPped on this host except the LLM-cage mark (needs `CAP_NET_ADMIN` for nft/iptables). Inspect `GET /api/v1/runtime/llm-vendor-cut`. Full operator doc: [WORLD_CAGE_AND_BROWSER.md](WORLD_CAGE_AND_BROWSER.md).
