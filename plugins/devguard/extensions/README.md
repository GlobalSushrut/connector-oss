# DevGuard IDE Extensions

DevGuard now exposes a local extension status API for IDE plugins:

- Endpoint: `GET http://127.0.0.1:7788/devguard/status`
- Started automatically by `devguard start`
- Can be run manually:
  - `devguard serve-status --session <session_id>`

## Status Payload

```json
{
  "current_session": "dg_xxx",
  "active_role": "mid_developer",
  "pending_approvals_count": 1,
  "budget_remaining": {
    "tokens_remaining": 21900,
    "max_tokens_per_task": 30000
  },
  "last_blocked_action": "exec.deny"
}
```

## Included Scaffolds

- `plugins/devguard/extensions/vscode` — VS Code extension scaffold
- `plugins/devguard/extensions/windsurf` — Windsurf extension scaffold

Both extensions poll `/devguard/status` every 2 seconds and render:

- role
- budget remaining
- pending approvals
- red status badge when approvals are pending
