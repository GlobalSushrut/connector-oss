# LedgerLens — AI FinOps for ConnectorOS

> **"We were burning $47K/month on GPT-4 calls. LedgerLens told us which team, which agent, and that 61% of it could shift to GPT-4o-mini with no quality loss. We cut $29K in two weeks."**

LedgerLens is the cost intelligence layer for AI-native companies.  
It plugs into ConnectorOS in minutes and gives your CFO a live dashboard with real dollar numbers, not dashboards that require a PhD to read.

---

## What it does in 60 seconds

| Problem | LedgerLens answer |
|---|---|
| "How much are we spending on AI today?" | `GET /api/v1/dashboard` — live burn rate, MTD, projected month-end |
| "Which team is responsible for the spike?" | Chargeback pivot by BU / team / customer — download as CSV |
| "Why did cost jump 4× last night?" | Anomaly detector fires Slack/PagerDuty alert with spike ratio |
| "Are we going to blow our budget?" | Budget envelopes with 4 policies: alert, downgrade, hard-stop, queue |
| "What should I cut first?" | Ranked savings recommendations with monthly $ and quality impact |
| "Can I send this to finance?" | HMAC-signed CFO export package — Excel-ready CSV, 1 click |

---

## The three calls that close deals

These work on **your own data**. Point a prospect at their own stack and run these.

### 1. Executive dashboard — "Is my AI spend under control?"

```bash
curl -s -H "X-API-Key: $KEY" \
  http://localhost:8085/api/v1/dashboard/executive | jq
```

```json
{
  "status": "🔴 CRITICAL — Action required today",
  "verdict": "You have 2 breached budget(s) and 1 critical anomaly. Your AI spend is running at $1.57K/day. Left unchecked, that's $47.10K this month. There is $14.20K in recoverable savings identified right now.",

  "this_month": {
    "spend_to_date":          "$31.40K",
    "daily_run_rate":         "$1.57K",
    "projected_month_end":    "$47.10K",
    "vs_last_month_pct":      "+34.2%",
    "annualised_run_rate":    "$565.20K",
    "annualised_with_savings":"$394.20K",
    "you_could_save":         "$171.00K"
  },

  "accountability_gap": {
    "untagged_spend":  "$12.80K",
    "untagged_pct":    "41%",
    "verdict": "41% of your AI spend has no owner. You cannot chargeback what you cannot attribute."
  },

  "biggest_cost_driver": {
    "agent":          "billing-agent-v2",
    "model":          "gpt-4o",
    "spend_usd":      "$18.20K",
    "pct_of_total":   "58%",
    "verdict":        "One agent (billing-agent-v2) on gpt-4o accounts for 58% of your entire AI bill this month."
  },

  "best_action_today": {
    "title":           "Rightsize billing-agent-v2 from gpt-4o → gpt-4o-mini",
    "saves_per_month": "$4.32K",
    "saves_per_year":  "$51.84K",
    "how":             "Switch billing-agent-v2 from gpt-4o → gpt-4o-mini. One API call applies it.",
    "apply_endpoint":  "/api/v1/recommendations/abc123/apply"
  }
}
```

---

### 2. Savings simulator — "What did we overpay last month?"

```bash
curl -s -X POST -H "X-API-Key: $KEY" \
  http://localhost:8085/api/v1/simulate/savings | jq
```

```json
{
  "headline": "Last month you spent $43.20K. With LedgerLens, you would have spent $26.90K. That's $16.30K (37.7%) you paid for nothing.",

  "actual_spend":    "$43.20K",
  "simulated_spend": "$26.90K",
  "total_saving":    "$16.30K",
  "saving_pct":      "37.7%",

  "breakdown": [
    { "lever": "Model rightsizing",    "saving": "$10.20K", "action": "Run POST /api/v1/optimize" },
    { "lever": "Eliminate failed calls","saving": "$2.10K",  "action": "Fix agent error handling" },
    { "lever": "Budget enforcement",   "saving": "$2.80K",  "action": "Set breach_policy=hard_stop" },
    { "lever": "Prompt caching",       "saving": "$1.20K",  "action": "GET /api/v1/cache-roi" }
  ],

  "annualised": {
    "actual_run_rate":  "$518.40K",
    "with_ledgerlens":  "$322.80K",
    "annual_saving":    "$195.60K"
  }
}
```

---

### 3. ROI calculator — "Does this tool pay for itself?"

```bash
curl -s -H "X-API-Key: $KEY" \
  "http://localhost:8085/api/v1/roi?monthly_cost_usd=299" | jq
```

```json
{
  "headline": "LedgerLens costs $299.00 /mo and saves $16.30K /mo on your stack. It pays for itself in 1 days. Annual ROI: 654×.",

  "your_monthly_ai_spend":    "$43.20K",
  "ledgerlens_monthly_cost":  "$299.00",
  "estimated_monthly_saving": "$16.30K",
  "roi_multiple":             "54.5×",
  "payback_days":             "1 days",
  "annual_saving":            "$195.60K"
}
```

---

## One-command setup

```bash
# 1. Clone and configure
cp plugins/ledgerlens/.env.example plugins/ledgerlens/.env
# Edit DATABASE_URL, CONNECTOR_URL, LEDGERLENS_API_KEY

# 2. Run migrations + start
cd plugins/ledgerlens
cargo run

# 3. Open dashboard
curl -H "X-API-Key: $LEDGERLENS_API_KEY" http://localhost:8085/api/v1/dashboard | jq
```

---

## Live dashboard — the one endpoint your CFO needs

```bash
curl -s -H "X-API-Key: $KEY" http://localhost:8085/api/v1/dashboard | jq
```

```json
{
  "signal": "🔴 ACTION REQUIRED",
  "spend": {
    "mtd_usd": "$47.23K",
    "daily_run_rate_usd": "$1.57K",
    "projected_month_end_usd": "$48.67K",
    "burn_rate": {
      "last_1h_usd": "$62.40",
      "last_24h_usd": "$1.57K",
      "last_7d_usd": "$10.99K",
      "trend": "↑ accelerating"
    }
  },
  "model_mix": {
    "frontier_pct": "78.3%",
    "insight": "⚠ 78% of spend on frontier models — rightsizing could save ~$810/mo"
  },
  "budgets": {
    "breached": 2,
    "utilisation_pct": "94.1%"
  },
  "anomalies": { "open_count": 1 },
  "savings": {
    "total_possible_per_month_usd": "$14.20K",
    "top_3": [
      { "title": "Rightsize billing-agent from gpt-4o → gpt-4o-mini", "saves_per_month": "$4.32K" },
      { "title": "Rightsize report-gen from claude-3-opus → haiku",   "saves_per_month": "$3.80K" },
      { "title": "Enable prompt caching for search-agent",            "saves_per_month": "$2.10K" }
    ]
  }
}
```

---

## Real-time burn rate

```bash
curl -s -H "X-API-Key: $KEY" \
  "http://localhost:8085/api/v1/costs/realtime" | jq '.windows'
```

```json
[
  { "window": "1h",  "spend_usd": "$62.40",  "hourly_rate_usd": "$62.40",  "vs_prior_period": "↑" },
  { "window": "24h", "spend_usd": "$1.57K",  "hourly_rate_usd": "$65.42",  "vs_prior_period": "↑" },
  { "window": "7d",  "spend_usd": "$10.99K", "hourly_rate_usd": "$65.42",  "vs_prior_period": "→" }
]
```

---

## Ingest a usage record with business tags

```bash
curl -s -X POST http://localhost:8085/api/v1/ingest \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{
    "agent_id":    "billing-agent-v2",
    "model":       "gpt-4o",
    "cost_usd":    0.0184,
    "input_tokens": 1200,
    "output_tokens": 340,
    "tag_bu":       "finance",
    "tag_team":     "billing",
    "tag_customer": "acme-corp",
    "tag_feature":  "invoice-generation"
  }'
```

---

## Set a budget with Slack alerts

```bash
# Create budget
curl -s -X POST http://localhost:8085/api/v1/budgets \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{
    "name":          "Finance BU Monthly",
    "scope_type":    "bu",
    "scope_value":   "finance",
    "period":        "monthly",
    "limit_usd":     5000,
    "breach_policy": "hard_stop",
    "alert_pct":     80,
    "alert_emails":  ["cfo@company.com"]
  }'

# Wire Slack channel
curl -s -X POST http://localhost:8085/api/v1/channels \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{
    "name":         "finops-slack",
    "channel_type": "slack",
    "config":       { "webhook_url": "https://hooks.slack.com/services/T.../B.../..." }
  }'

# Fire test alert to verify wiring
curl -s -X POST http://localhost:8085/api/v1/channels/$CHANNEL_ID/test \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"message": "LedgerLens is live. Budget alerts are wired."}'
```

---

## Download chargeback CSV (opens in Excel)

```bash
curl -s -H "X-API-Key: $KEY" \
  "http://localhost:8085/api/v1/csv/chargeback?from=2025-04-01&to=2025-04-30" \
  -o chargeback-april.csv
```

Output:
```
Period Start,Period End,Business Unit,Team,Workflow,Model,Provider,Calls,Input Tokens,Output Tokens,Total Tokens,Cost USD,% of Total
2025-04-01,2025-04-30,finance,billing,invoice-generation,gpt-4o,openai,8420,9124800,2876400,12001200,154.820000,32.81
2025-04-01,2025-04-30,engineering,search,semantic-search,gpt-4o-mini,openai,62100,31050000,12420000,43470000,93.150000,19.75
...
TOTAL,,,,,,,,,,, 471.940000,100.00
```

---

## All endpoints

### Dashboard
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/dashboard` | CFO money-on-fire summary |
| GET | `/api/v1/costs/realtime` | Live burn rate by window + model |

### Cost Attribution
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/ingest` | Ingest usage with business tags |
| POST | `/api/v1/sync` | Pull latest from ConnectorOS |
| GET | `/api/v1/costs?pivot=bu&from=...&to=...` | Multi-dim cost pivot |
| GET | `/api/v1/costs/fleet` | Fleet-wide summary |
| GET | `/api/v1/costs/agents/:id` | Per-agent cost breakdown |

### Budgets
| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/budgets` | List / create budget envelopes |
| GET/DELETE | `/api/v1/budgets/:id` | Get / delete budget |
| GET | `/api/v1/budgets/:id/events` | Breach + warn history |
| GET | `/api/v1/budgets/status` | All budgets with utilisation % |

### Anomalies
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/anomalies` | Open anomalies, severity-sorted |
| POST | `/api/v1/anomalies/:id/acknowledge` | Ack with note |
| POST | `/api/v1/anomalies/:id/resolve` | Mark resolved |

### Forecasting
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/forecast?horizon_days=30` | p50/p80/p95 spend projection |

### Optimization
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/waste` | Waste heatmap with $ impact |
| GET | `/api/v1/cache-roi` | Cache ROI by agent |
| POST | `/api/v1/optimize` | Run rightsizing engine |
| GET | `/api/v1/recommendations` | All open savings recommendations |
| POST | `/api/v1/recommendations/:id/apply` | Apply (pushes to ConnectorOS) |
| POST | `/api/v1/recommendations/:id/dismiss` | Dismiss with reason |

### CSV Exports (Excel-ready)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/csv/chargeback?from=&to=` | Chargeback by BU/team |
| GET | `/api/v1/csv/unit-economics?from=&to=` | Cost vs revenue by customer |
| GET | `/api/v1/csv/waste` | Waste report with savings |
| GET | `/api/v1/csv/anomalies?from=&to=` | Anomaly history |

### CFO Package (HMAC-signed JSON)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/exports` | Create export job |
| POST | `/api/v1/exports/:id/run` | Run and sign export |
| GET | `/api/v1/exports/:id` | Poll status + download URL |

### Notifications
| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/channels` | List / create alert channels |
| POST | `/api/v1/channels/:id/test` | Fire test alert immediately |

### Revenue / Unit Economics
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/revenue` | Record revenue for a customer/feature |

---

## Environment variables

```bash
DATABASE_URL=postgres://user:pass@localhost:5432/ledgerlens
CONNECTOR_URL=http://localhost:8080
LEDGERLENS_API_KEY=your-api-key-here

PORT=8085
METRICS_PORT=9091

BUDGET_SWEEP_SECS=60       # How often enforcement sweeper runs
COST_SYNC_SECS=300         # How often to pull usage from ConnectorOS
ANOMALY_WINDOW_HOURS=1     # Rolling window for anomaly detection
ANOMALY_MULTIPLIER=3.0     # Spike threshold (3× baseline = anomaly)

LEDGERLENS_HMAC_KEY=your-signing-key   # For tamper-evident CFO exports
RUST_LOG=ledgerlens=info
```

---

## Prometheus metrics

All metrics available at `:9091/metrics`.

| Metric | Labels | Description |
|--------|--------|-------------|
| `ledgerlens_records_ingested_total` | provider, model | Usage records ingested |
| `ledgerlens_cost_ingested_usd_total` | — | Total cost ingested (microdollars) |
| `ledgerlens_budget_warnings_total` | scope | Budget warn threshold hits |
| `ledgerlens_budget_breaches_total` | scope, policy | Budget breaches |
| `ledgerlens_anomalies_detected_total` | dimension, severity | Anomalies found |
| `ledgerlens_recommendations_applied_total` | type | Optimizations applied |
| `ledgerlens_exports_completed_total` | type | Export jobs completed |
| `ledgerlens_alerts_dispatched_total` | channel_type, event | Alerts fired |
| `ledgerlens_alert_failures_total` | channel_type | Alert delivery failures |
| `ledgerlens_errors_total` | code, status | All API errors |
| `ledgerlens_request_duration_seconds` | method, path, status | Request latency |

---

## Architecture

```
                     ┌─────────────────────────────────────┐
                     │           LedgerLens                │
                     │                                     │
  ConnectorOS  ────► │  sync → attribution → budgets       │
  (usage data)       │            ↓                        │
                     │       forecasting                   │
  Your agents ─────► │  ingest ──┤                        │
  (tag on call)      │           ↓                        │
                     │       anomalies → alerts            │
                     │            ↓                        │
                     │       optimize → recommendations    │
                     │            ↓                        │
                     │    dashboard / CSV / exports        │
                     └─────────────────────────────────────┘
                               │
                    ┌──────────┼──────────┐
                 Postgres    Slack    PagerDuty
```

---

## Enforcement policies

When a budget is breached, LedgerLens acts — it doesn't just email:

| Policy | Effect |
|--------|--------|
| `alert_only` | Fires Slack/PagerDuty/webhook, continues |
| `downgrade` | Writes recommended model into ConnectorOS insights so next call uses cheaper model |
| `hard_stop` | Sets `breached=true` — your agents check `GET /api/v1/budgets/status` and stop |
| `cap_and_queue` | Same as hard_stop until period resets automatically |

---

*LedgerLens is part of the ConnectorOS plugin suite.*  
*License: see `/platform/LICENSE`*
