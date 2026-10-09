# LedgerLens — AI FinOps Plugin for ConnectorOS

> **LedgerLens is the cost intelligence layer for AI-native companies. It tells you exactly how much you're spending on AI, who is responsible for it, what's wasted, and what to do about it — in one API call.**

---

## The Problem

Every company running AI agents in production has the same five problems:

1. **The invoice arrives. Nobody knows what generated it.** OpenAI sends a $47,000 bill. Engineering looks at it. Finance looks at it. Nobody can say which product, which team, or which feature caused which cost. The only option is to pay it.

2. **Budgets are set in spreadsheets, enforced in conversations.** "We agreed to keep AI costs under $5K/month for the finance team." Actual enforcement: a Slack message from the CFO at month-end. By then it's already $9,200.

3. **The most expensive model is used for everything.** GPT-4o costs 10× more than GPT-4o-mini. Without visibility, every agent defaults to the most capable model because there's no cost signal. 70% of those calls would produce identical output on the cheaper model.

4. **Cost spikes go undetected for days.** An agent bug causes a retry loop. 14,000 API calls happen in 2 hours. Nobody notices until the cloud bill arrives three weeks later.

5. **Finance cannot understand AI cost.** The CFO cannot chargeback AI spend to business units because nobody tagged the calls with business context when they were made. The cost center "AI" grows unchecked.

LedgerLens solves all five.

---

## What It Is

LedgerLens is a ConnectorOS plugin that runs alongside your agent fleet. It:

- **Ingests every AI API call** with business tags (BU, team, customer, feature, workflow)
- **Enforces budget envelopes** with four policies: alert, downgrade, hard-stop, queue
- **Detects spend anomalies** in real time and fires Slack/PagerDuty/OpsGenie alerts
- **Projects month-end spend** with p50/p80/p95 confidence intervals
- **Identifies savings** by comparing model choices against quality/cost tradeoffs
- **Produces chargeback reports** as Excel-ready CSV — signed, auditable, shareable

All of this runs on your own infrastructure. Data never leaves your environment.

---

## Architecture

```
                        ┌─────────────────────────────────────────────────┐
                        │                  LedgerLens                     │
                        │                                                 │
  Your AI agents ─────► │  POST /api/v1/ingest  (tag every call)         │
  (tag at call time)     │         │                                       │
                        │         ▼                                       │
  ConnectorOS ────────► │  Background sync ──► attribution engine        │
  (usage export)        │                           │                     │
                        │                    ┌──────┴──────┐              │
                        │                    │             │              │
                        │               budgets        forecasting        │
                        │                    │             │              │
                        │               enforcement   anomaly detection   │
                        │                    │             │              │
                        │               alerts ◄──────────┘              │
                        │         (Slack / PagerDuty / OpsGenie)         │
                        │                    │                            │
                        │              optimize engine                    │
                        │         (rightsizing + cache ROI)              │
                        │                    │                            │
                        │    dashboard / CSV exports / CFO package        │
                        └─────────────────────────────────────────────────┘
                                          │
                               ┌──────────┴──────────┐
                           Postgres              Prometheus
                          (all data)           (:9091/metrics)
```

---

## The Five Modules

### 1. Cost Attribution

Every AI API call can carry business tags:

```json
{
  "agent_id":    "billing-agent-v2",
  "model":       "gpt-4o",
  "cost_usd":    0.0184,
  "tag_bu":      "finance",
  "tag_team":    "billing",
  "tag_customer":"acme-corp",
  "tag_feature": "invoice-generation"
}
```

LedgerLens stores these, pulls historical data from ConnectorOS on a schedule, and can pivot cost by any dimension:

```bash
GET /api/v1/costs?pivot=bu&from=2025-04-01&to=2025-04-30
GET /api/v1/costs?pivot=customer
GET /api/v1/costs?pivot=model
GET /api/v1/costs?pivot=feature&tag_bu=finance
```

Every pivot response includes total USD, token counts, call counts, and percentage of total — ready for chargeback.

---

### 2. Budget Enforcement

Create a budget envelope for any dimension:

```json
{
  "name":         "Finance BU Monthly",
  "scope_type":   "bu",
  "scope_value":  "finance",
  "period":       "monthly",
  "limit_usd":    5000,
  "breach_policy":"hard_stop",
  "alert_pct":    80
}
```

**Four enforcement policies:**

| Policy | What happens at breach |
|---|---|
| `alert_only` | Fires Slack/PagerDuty/webhook, continues serving calls |
| `downgrade` | Writes recommended model into ConnectorOS — next calls use cheaper model |
| `hard_stop` | Sets `breached=true` — agents check `/api/v1/budgets/status` and stop |
| `cap_and_queue` | Hard-stop until period auto-resets |

The enforcement sweeper runs every 60 seconds (configurable). Budget periods reset automatically at period boundaries. No manual intervention required.

---

### 3. Anomaly Detection

The anomaly detector runs on a configurable schedule. For each dimension (global, by feature, by BU), it compares spend in the current window against the same time window over the last 7 days. If current spend exceeds baseline by more than the configured multiplier (default: 3×), an anomaly is created and alerts fire immediately.

```
Baseline: $12.40 in the last hour (7-day average for this hour-of-day)
Current:  $54.20 in the last hour
Spike:    4.4×  ← fires critical anomaly, Slack + PagerDuty
```

Anomalies carry structured context: which agents drove the spike, which models, top-5 cost contributors. The on-call engineer has everything they need to respond without running queries.

---

### 4. Forecasting

For any dimension, LedgerLens projects spend over 30/60/90 days using a weighted average of trailing-7d (2×) and trailing-30d (1×) daily run rates:

```json
{
  "p50_usd":           "$48,200",
  "p80_usd":           "$54,600",
  "p95_usd":           "$61,000",
  "daily_avg_usd":     "$1,570",
  "growth_rate_pct":   "+12.4%",
  "scenarios": {
    "conservative": "$43,800",
    "base":         "$48,200",
    "aggressive":   "$58,900"
  }
}
```

Budget owners can set spend limits against the p80 forecast — the most operationally useful number for planning.

---

### 5. Optimization Engine

The optimizer analyses model usage patterns and produces ranked savings recommendations:

- **Model rightsizing**: identifies agents using GPT-4 class models for tasks where GPT-4o-mini produces equivalent quality. Uses ConnectorOS fleet data to compare quality scores across the fleet.
- **Prompt cache ROI**: identifies high-frequency agents where prompt caching would have significant hit rates, with $ savings estimate.
- **Idle agent detection**: agents that haven't been called in 7+ days but still have allocated budget.
- **Zero-output waste**: calls that return empty completions but are still billed — signals broken retry logic or misconfigured prompts.

Recommendations are ranked by monthly savings and can be applied with a single API call — which pushes the change to ConnectorOS directly.

---

## The Executive Layer

Three endpoints exist specifically for the CFO conversation:

**`GET /api/v1/dashboard/executive`** — Not metrics. Verdicts.

```json
{
  "status": "🔴 CRITICAL — Action required today",
  "verdict": "You have 2 breached budgets and 1 critical anomaly. Your AI spend is running at $1.57K/day. There is $14.20K in recoverable savings identified right now.",
  "biggest_cost_driver": {
    "verdict": "One agent (billing-agent-v2) on gpt-4o accounts for 58% of your entire AI bill this month."
  },
  "best_action_today": {
    "saves_per_year": "$51.84K",
    "how": "Switch billing-agent-v2 from gpt-4o → gpt-4o-mini. One API call applies it."
  }
}
```

**`POST /api/v1/simulate/savings`** — Runs against historical data to show what last month's bill would have been with LedgerLens active.

**`GET /api/v1/roi?monthly_cost_usd=299`** — LedgerLens' own ROI on the customer's stack.

---

## Outputs

| Output | Format | How to get it |
|---|---|---|
| Chargeback report | Excel CSV | `GET /api/v1/csv/chargeback?from=&to=` |
| Unit economics | Excel CSV | `GET /api/v1/csv/unit-economics?from=&to=` |
| Waste report | Excel CSV | `GET /api/v1/csv/waste` |
| CFO package | HMAC-signed JSON | `POST /api/v1/exports` + run |
| Live dashboard | JSON | `GET /api/v1/dashboard/executive` |
| Prometheus metrics | Prometheus text | `:9091/metrics` |

All CSV exports include totals rows and open natively in Excel and Google Sheets without import configuration.

HMAC-signed exports use a configurable key (`LEDGERLENS_HMAC_KEY`) — the signature covers the entire payload, making them tamper-evident for audit and compliance handoffs.

---

## Notification Channels

LedgerLens dispatches alerts to:

| Channel | Config |
|---|---|
| **Slack** | `webhook_url` — colour-coded by severity (red/orange/yellow/green) |
| **PagerDuty** | `routing_key` — severity maps to P1–P4 automatically |
| **OpsGenie** | `api_key` — severity maps to priority levels |
| **Generic webhook** | `url` + optional `secret` for HMAC-signed payloads |

Each channel is created once via `POST /api/v1/channels`. Rules link event types (`budget_breach`, `budget_warn`, `anomaly`, `all`) to channels. Fire a test immediately with `POST /api/v1/channels/:id/test` — no waiting for a real breach to verify wiring.

---

## Integration Points

**ConnectorOS kernel**: LedgerLens uses ConnectorOS as the source of truth for raw usage records, model quality scores, and applied recommendations. The sync runs on a configurable schedule (default: every 5 minutes).

**AgentLoop**: When a budget is breached with `downgrade` policy, LedgerLens writes the recommended model into ConnectorOS. AgentLoop picks this up at the mesh layer and routes the next call accordingly — no agent code changes required.

**Grafana**: All 17 Prometheus metrics are labelled consistently. Import-ready dashboard JSON is served by the platform kernel at `GET /api/v1/monitor/grafana-dashboard` (same payload shape as the old on-disk export).

---

## Deployment

LedgerLens runs as a single Rust binary. No runtime dependencies beyond Postgres.

```bash
DATABASE_URL=postgres://...
CONNECTOR_URL=http://connector:8080
LEDGERLENS_API_KEY=your-key
PORT=8085
METRICS_PORT=9091
```

Auto-migrates on startup. Docker image via the workspace `Dockerfile`. Helm chart at `platform/deploy/helm/`.
