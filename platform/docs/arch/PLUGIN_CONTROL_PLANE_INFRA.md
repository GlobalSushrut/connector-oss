# Plugin control plane — operator env & probes

This note is for **Connector platform** (`platform/server`) operators wiring the Leptos **Plugins** hub and dashboards.

**Bootstrap env template:** `platform/deploy/.env.example` (kernel boot only — no plugin secrets). Plugin management URLs and tokens are set on the **platform process** (shell, systemd, or future Settings → Plugins); see table below and `CONNECTOR_CAGE_NODE_AND_PLUGINS.md`.

## `GET /api/v1/plugins/status`

Returns non-secret JSON per plugin:

| Plugin | Env (primary) | Probe (when URL/token set) | UI |
|--------|----------------|----------------------------|-----|
| **TraceTramp** | `CONNECTOR_TRACETRAMP_ADMIN_TOKEN` (or `TRACETRAMP_ADMIN_TOKEN`); optional `CONNECTOR_TRACETRAMP_MANAGEMENT_URL` | `GET {base}/admin/stats` with Bearer | Hub + `/plugins/tracetramp` via server proxy |
| **WitnessCtl** | Optional `CONNECTOR_WITNESSCTL_MANAGEMENT_URL` (or `WITNESSCTL_MANAGEMENT_URL`) | `GET {base}/health` | Hub badge; `/plugins/witnessctl` embedded shell (no JSON proxy yet) |
| **DevGuard** | Optional `CONNECTOR_DEVGUARD_MANAGEMENT_URL` (or `DEVGUARD_MANAGEMENT_URL`) | `GET {base}/devguard/status`, else `GET {base}/health` | Hub badge; `/plugins/devguard` embedded shell |

Fields exposed to the UI (no secrets): `configured` / `management_proxy_configured`, `management_url_explicit`, `management_display_host` (host:port only), `upstream_reachable` (`true` / `false` / omitted), `hint`, `dashboard_path`.

## Production checklist

1. **TraceTramp**: set admin token on the **platform** process so browser never sees it; confirm probe and TraceTramp proxy routes succeed from the same host network as `{management}`.
2. **WitnessCtl / DevGuard**: set management base URLs only to reachable addresses from the platform container (same Docker network or mesh), not `localhost` unless the process shares the network namespace.
3. **Firewall**: outbound HTTPS from platform to plugin management URLs must be allowed for probes and TraceTramp proxy traffic.

## Related code

- `platform/server/src/services/plugins_status.rs` — aggregates JSON.
- `platform/server/src/services/plugin_upstream_probe.rs` — WitnessCtl / DevGuard HTTP probes.
- `platform/server/src/services/tracetramp_proxy.rs` — TraceTramp admin forward + probe.
