# 32 — connectorctl CLI Reference

> Every verb, noun, and selector in the connectorctl command-line interface.

---

## Mental model: node first, then apps

Operators should think in two beats: **(1) bring the Connector OS node up**, **(2) bring individual workloads (“apps”) up** and read how to reach them.

- **Node up** — Start **`connector-platform`** (e.g. **`connectorctl start`**, foreground or supervised). Colloquially this is “connector up”: one governed HTTP runtime + embedded dashboard unless **`CONNECTOR_UI_DIR`** overrides it.
- **List / discover apps** — **`connectorctl app list`** (and **`app show <id>`**) call **`GET /api/v1/apps`** — one table of **plugins + workflows** with `status_badge`, `active`, `port`, `uri` / `public_uri`, `cage_host`, and suggested `actions`. Filter with **`--kind plugin`** or **`--kind workflow`**. Legacy split: **`connectorctl workflow list`**, **`GET /api/v1/plugins/status`**, **`connectorctl health` / `status` / `doctor`**. **Direction:** automatic registration when new workflow packages land (no per-artifact CLI treadmill) — **`ARCHITECTURE.md`** § *Operator story*.
- **App up + wiring** — Enable a workflow (**`connectorctl workflow enable <id>`** today), install/enable plugins, or run host/lab setup for computer-level tools (e.g. DevGuard). **Direction:** **up** from the **same catalog row** (UI / API) as listing, especially at high workflow count. When something is active, you care about **state**, **PID** (if supervised), **port**, and **URI** for other agentic components to connect; health and plugin status output are the current sources of truth.

Setup **differs by app class** (in-kernel workflow vs host-integrated tool); the abstract loop is the same. Full narrative: **`ARCHITECTURE.md`** (same section title).

---

## Apps catalog (unified list)

```bash
connectorctl app list                      # plugins + workflows (GET /api/v1/apps)
connectorctl app list --kind plugin        # plugins only
connectorctl app list --kind workflow      # workflows only
connectorctl app list --json
connectorctl app show tracetramp             # one row: port, uri, cage_host, actions
connectorctl app show my-workflow-id
```

Columns include **`status_badge`**, **`active`**, **`port`**, **`uri`** / **`public_uri`**, **`cage_host`**, and suggested **`actions`**. **`pid`** is reserved for kernel-supervised processes (future).

---

## Installation

```bash
# If Connector server is installed, connectorctl is included
which connectorctl

# Or install standalone
curl -fsSL https://install.connector.ai/ctl | bash
```

---

## Global Flags

```
--url <URL>      Connector node URL (default: $CONNECTOR_URL or http://localhost:9091)
--key <KEY>      API key (default: $CONNECTOR_API_KEY)
--output json    Output as JSON (default: human-readable table)
--output yaml    Output as YAML
--quiet          Suppress decorative output
--verbose        Show raw HTTP request/response
```

---

## Health

```bash
connectorctl health                    # Node health summary
connectorctl health --detail           # Full ring status
```

Text **`connectorctl status`** and **`connectorctl doctor`** print **Process env (API):** when **`GET /api/v1/plugins/status`** includes **`phase_5_operator`** (uses **`process_env_operator_display_line`** from the API when present, else the same formatting as **`connect_*`** / **`production_dev_mode_hygiene`**). **`connectorctl status --json`** and **`connectorctl doctor --json`** both duplicate that string at the top level as **`process_env_operator_display_line`** when the API returns it (easy **`jq -r .process_env_operator_display_line`**); **`doctor --json`** also keeps a copy under **`doctor_extensions.process_env_operator_display_line`**.

---

## Host kernel preflight (repo)

From the repo root, before enabling host-side kernel enforcement (`platform/scripts/connector-kernel-prod-preflight.sh`):

```bash
make kernel-prod-preflight
# With connectorctl JSON checks (needs CONNECTOR_API_URL; jq or python3 for hygiene + process_env line invariants):
make kernel-prod-preflight-with-connector
```

---

## Agents

```bash
connectorctl agents                    # List all agents (table)
connectorctl agents --output json      # List as JSON

connectorctl inspect <pid>             # Inspect agent state
connectorctl show agent <pid>          # SOE-formatted summary (operator view)
connectorctl explain agent <pid>       # SOE explain surface

connectorctl agents create \
  --name my-agent \
  --role worker \
  --clearance 3

connectorctl agents kill <pid>         # Graceful shutdown
connectorctl agents unquarantine <pid> # Release from quarantine
```

---

## Tracing

```bash
connectorctl trace agent <pid>                  # Recent events
connectorctl trace agent <pid> --last 1h        # Last hour
connectorctl trace agent <pid> --last 24h       # Last 24 hours
connectorctl trace agent <pid> --memory         # Memory writes only
connectorctl trace agent <pid> --decisions      # Governance decisions only
connectorctl trace agent <pid> --tools          # Tool dispatches only
connectorctl trace agent <pid> --limit 100      # Limit results
```

---

## Proof and Audit

```bash
connectorctl prove agent <pid>                  # Generate proof bundle
connectorctl prove agent <pid> --title "q1"     # Named proof bundle
connectorctl prove agent <pid> --format json    # Export as JSON
connectorctl prove agent <pid> --format md      # Export as Markdown
connectorctl prove agent <pid> --export ./out/  # Save to directory

connectorctl explain <decision_id>              # Decision detail
connectorctl explain <receipt_id>              # Receipt detail
```

---

## Policy and Governance

```bash
connectorctl verify policy <path>              # Verify a policy file
connectorctl verify contract <path>            # Verify a CCL contract
connectorctl verify policies --all             # Check all loaded policies

connectorctl policy check <pid> <op> <ns>      # Check a specific policy
# Example:
connectorctl policy check pid:000005 mem_read /p/patients/p001
```

---

## Compliance

```bash
connectorctl compliance report soc2            # SOC2 compliance report
connectorctl compliance report hipaa           # HIPAA compliance report
connectorctl compliance report gdpr            # GDPR compliance report

connectorctl compliance violations             # Active policy violations
connectorctl compliance score                  # Overall compliance score
```

---

## Contracts (CCL / CLS)

```bash
connectorctl contracts compile <path.ccl>      # Compile CCL contract
connectorctl contracts list                    # List deployed contracts
connectorctl contracts inspect <cid>           # Inspect a contract
connectorctl deploy contract <cid> --agent <pid>  # Deploy to an agent
```

---

## Memory

```bash
connectorctl memory recall <namespace>         # Recall from namespace
connectorctl memory search <ns> "<query>"      # Semantic search
connectorctl memory stats <pid>                # Memory stats for agent
connectorctl memory tree <pid>                 # Memory tree structure
```

---

## HITL (Human-in-the-Loop)

```bash
connectorctl hitl list <pid>                   # List pending HITL requests
connectorctl hitl approve <pid> <request_id>   # Approve a request
connectorctl hitl deny <pid> <request_id>      # Deny a request
```

---

## Cost

```bash
connectorctl cost agent <pid>                  # Cost for one agent
connectorctl cost dashboard                    # All agents cost summary
connectorctl cost reset <pid>                  # Reset cost counter (dev only)
```

---

## Plugins

```bash
connectorctl plugins list                      # List loaded plugins
connectorctl plugins inspect <plugin_id>       # Plugin details
connectorctl plugins reload <plugin_id>        # Hot-reload a plugin
```

### Connector Hub (`.cpkg` registry)

Uses `CONNECTOR_API_URL` / `CONNECTOR_API_KEY` for kernel install paths; `CONNECTOR_HUB_URL` / `CONNECTOR_HUB_PUBLISH_TOKEN` for publish/yank when applicable.

```bash
connectorctl hub search [query]
connectorctl hub install <vendor/slug>[@version]
connectorctl hub update <vendor/slug>
connectorctl hub publish <file.cpkg>
connectorctl hub yank <vendor/slug> <version>
connectorctl hub uninstall <vendor/slug>
connectorctl hub bundle-export <out.zip> <vendor/slug[@ver]> ...
connectorctl hub bundle-import <bundle.zip> [--verify-health-sec <n>]
```

### Plugin thermal tier scheduler (Phase 5.4)

Wraps kernel `GET/POST` under `/api/v1/kernel/plugin-tier-*`. Pairs with `connectorctl plugin run --dev` (admit before spawn, touch after success). Aggregate snapshot also appears in `connectorctl status --json` (`tier_scheduler`) and `connectorctl doctor --json` (`doctor_extensions.tier_scheduler`) when the node responds. **`status --json`** and **`doctor --json`** also include **`shell_production_env`** (the shell running `connectorctl`; compare to **`phase_5_operator`** from **`GET /api/v1/plugins/status`**, including **`connect_*`** and **`production_dev_mode_hygiene`** for the live connector process). The dashboard shows it on **Service Map** (`#tier-scheduler`) and optionally on **Plugins** via **Load snapshot**.

```bash
connectorctl tier show [--json]
connectorctl tier admit <vendor/slug> [--budget-ms <ms>]
connectorctl tier touch <vendor/slug>
```

### AGOS (`plugin.toml` / Connector OS)

```bash
cargo install --path cargo-connector           # from repo root: Cargo subcommand `cargo connector`
cargo connector new local/my-plugin            # scaffold plugin.toml + Rust binary
connectorctl plugin verify . [--json] [--require-kernel]
connectorctl plugin run --dev local/my-plugin [-- <args>…]
connectorctl plugin run --dev --watch local/my-plugin   # subprocess: re-run after exit 0 when plugin.toml/entrypoint changes
```

Authoring walkthrough (hello world in 30 lines): **[AGOS — Plugin authoring](agos/plugin-authoring.md)**. ABI policy: **[AGOS — ABI versioning](agos/abi-versioning.md)**.

---

## Output Formats

```bash
# Table (default)
connectorctl agents
# ┌─────────────────────────────────────────┬──────────────┬────────┐
# │ PID                                     │ NAME         │ STATUS │
# ├─────────────────────────────────────────┼──────────────┼────────┤
# │ agent_e1e311894a474dc7b4cfa91b3caa1821  │ my-agent     │ ACTIVE │
# └─────────────────────────────────────────┴──────────────┴────────┘

# JSON
connectorctl agents --output json
# {"agents": [...], "count": 1}

# YAML
connectorctl agents --output yaml
```

---

## `show agent` Output Format

```
── agent_abc123 ── ACTIVE │ VERIFIED │ COMPLIANT  trust:85/A  cid:soe1-sha256-
agent_abc123: my-agent | 42 decisions | active 2h 15m

  ✓ Evidence verified
  ✓ Health: HEALTHY
  ✓ Compliance: COMPLIANT

Decision: ALLOW — summarize.patient_record
Action: Record patient summary with HIPAA tagging
Trust: Verified evidence chain
Why: Confidence 0.95, minimum necessary access enforced
Risk: LOW — PHI fenced, chain verified
Compliance: ✓ HIPAA ✓ SOC2
```

---

## `explain` Output Format

```
Decision: dec_63de9107-d5c8-4fa4-a59b-c6b27db15c8b
Action:   summarize.patient_record
Target:   /p/patients/p001
Outcome:  allow_minimum_necessary
Confidence: 0.95
Rationale:  Attending physician access, treatment purpose
Regulations: [hipaa, soc2]
Audit CID:  mem1-sha256-abc...
Chain verified: true
Agent health: 85/A
Immutable: true
Signed: ed25519:34d0bdcb...
```

---

## Scripting with connectorctl

```bash
#!/bin/bash
# CI/CD governance gate script

PID=$(connectorctl agents --output json | jq -r '.agents[0].pid')
PROOF=$(connectorctl prove agent "$PID" --output json | jq -r '.proof_id')
GRADE=$(connectorctl compliance score --output json | jq -r '.grade')

if [[ "$GRADE" == "A" || "$GRADE" == "B" ]]; then
  echo "✓ Governance gate passed: $PROOF"
  exit 0
else
  echo "✗ Governance gate failed: grade=$GRADE"
  exit 1
fi
```

---

## Next Steps

- **[26 — API Overview](26-api-overview.md)**
- **[04 — Python SDK](04-python-sdk.md)**
- **[01 — Quickstart](01-quickstart.md)**
