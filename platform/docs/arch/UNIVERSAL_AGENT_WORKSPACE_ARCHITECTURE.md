# Universal agent workspace

**Status:** Projection plus character, directive, and alias records. HTTP mutating routes and plugin-cage mutations are on one PATE task or are refused before execution, or they are declared non-effects. The agentgateway v1.6.0 registry digest is pinned. The process is not installed and its acceptance suite has not passed.

Connector governs intelligence through to consequence: identity, contract, grant, context and memory, one PATE admission, runtime enforcement, observed effect, receipt, memory consequence, and Cease. The workspace is how an operator sees that government. It is not a second memory backend and not a second admission authority.

The seven workspace dimensions are governance dimensions. They are not the seven external backends. Files, knowledge, memory, mutable state, and active context stay separate. Upload does not mean model context. A knowledge document is not a directive and does not grant authority.

## Status vocabulary

Each projected record is `present`, `absent`, `not_applicable`, or `externally_managed`. A missing store stays `absent`. The projection does not invent a grant, a context budget, an activation, or a purpose.

`production_ready`, `effect_mediated`, and `inventory_complete` stay separate. The projection reports `inventory_complete: true` for the HTTP route inventory and plugin-cage mutations. `production_ready` stays false until live seven-backend evidence. `effect_mediated` is per effect. Agentgateway stays `TARGET`. This is not Connector Ready.

## What the projection reads

`GET /api/v1/agents/:pid/workspace` composes existing records:

| Dimension | Source when present | When the named record is missing |
| --- | --- | --- |
| Principal | `intelligence_principal_v2` | `absent` |
| Purpose | Specific sentences on `agent_contract_v2` | `absent`, including a blank or general-purpose purpose |
| Presence | Model ref, continuity, and alias bindings | `absent` when none of those sources exist. Swarm membership stays `absent` and does not grant |
| Knowledge | Asset containers and file records for this agent | `absent`. Ingested knowledge is still not active context |
| Directives | `directive_v1` rows whose source is the operator | `absent` when none are stored. A knowledge document cannot be saved as a directive |
| Authority | Contract and existing grant rows | `absent` when neither is stored |
| Situation | Checkpoints and stored context state | `absent` when neither source exists. The projection is not task authority |

Memory packet counts come from the agent namespace when that agent is in the kernel. A context transfer stores an activation receipt that indexes the range, manifest, transfer, generation, and render digest. That receipt admits nothing. When no transfer has been stored, active context stays `absent`. Dropped context frames keep a reason code. Evidence lists `intelligence_receipt_v2` ids. Explain uses the receipt task when that task is stored, and otherwise the latest agent record, labeled `PARTIAL`.

PATE remains the only admission authority. Configuring a product task writes a model, a purpose, and an ask-only grant. That stage is configured. It is not executed.

## Not in this projection

Character text, operator directives, and aliases can be stored. None of them admit an effect. Delegation stores a child grant only when a parent `GrantRef` attenuates an ask-only grant. Native invocation, workbench turns, A2A sends, the memory and knowledge writes on the closed list, asset upload and ingest, agent lifecycle, debug restore, object-fabric puts, MCP dispatch, register, discover, handle, and protocol call, and multiagent grant, revoke, pipeline, and step approval close the same PATE task they admitted. Experiment runs, chat completions, and Anthropic messages close after the model call. An Ask on those runs stays open and does not call the model. Agent update, budget reset, budget update, clearance, and registration close the same task. Registration mints the contract, so a missing contract is not a block on that call. Runtime policy, mode, activation, isolation, pilot changes, agent setup and activate, and LLM settings writes, including the key link, close the same task. Prompt, webhook, plugin lifecycle, workspace file save and remove, git commit and push, notification cancel, workbench session create, chat thread create, and devguard session start and end close the same task. Webhook test does not send or store a delivery. API key create, knowledge-boundary writes, team membership, and the agent-loop turn close the same task. A workbench consult uses the chat completions task. Playground session end, analytics events, package lifecycle, and rollup policy writes close the same task. Agent kill, freeze, thaw, token revoke, notification scan, and council mint, floor, membership, and close close the same task. Agent reset, trust, reflection, migrate, HITL, missions, and agent task assign close the same task. Monitor rules, experiments, history archive, tool approve and deny, action records, work proofs, pipeline writes, and the KECS health sweep close the same task. Notices, channels, cgroups, world grants, decision records, and browser page loads close the same task. An early return closes a Proceed chat task as unobserved. The protocol call performs HTTP before that close and records the call as observed only when the HTTP result returns. Other mutating HTTP methods close through a route shell on one PATE task. Declared non-effects and calls that already open a task are not given a second one. Ask stays open and the handler does not run. This document does not mark the product production-ready. agentgateway is not installed: `GET /runtime/agentgateway` reports `TARGET`, and ext-auth denies forwarding even after PATE Proceed. `inventory_complete` is that HTTP inventory. Seeded report-center rows are catalog routes, not effect receipts. `/setup` and `/setup/uplink` are panels of one editor.

`GET /api/v1/agents/:pid/preflight` reports `absent`, `model_only`, or `inventory_unknown`. A stored file stays stored. An ingested file stays ingested and keeps a source-version row for the ingest parser. An ingested source can be marked eligible, then linked to a stored activation. That link is not model context. The workspace projection still does not treat the file as active context. A directive supersession stays inactive and is recorded in activation history. `GET /agents/:pid/presence` and `POST /agents/:pid/situation` are read models over kernel status, parentage, checkpoints, and a stored task. `DELETE /tools/mcp/bridges/:bridge_id` removes a bridge record and admits nothing.

Machine-readable status: [workspace-implementation-status.json](workspace-implementation-status.json). Remaining work: [WORKSPACE_REMAINING.md](WORKSPACE_REMAINING.md).
