# LedgerLens — Implementation Plan

> **Your AI bill is $2M. You can't explain why. LedgerLens can.**

**AI FinOps and cost attribution platform** — built on Connector.

---

## 1. The Problem (validated 2026 signal)

The 2026 State of FinOps Report: *"Teams are flying blind on AI cost."*

Enterprise reality today:
- Annual AI inference spend: **$500K → $10M+** and growing
- Finance team gets **one bill** from OpenAI/Anthropic/Azure
- **Zero attribution** by feature, business unit, customer, workflow, team
- No unit economics: is the AI feature saving $4/customer or costing $7/customer? Nobody knows.
- No chargeback: Marketing uses AI in 40% of features, Engineering pays 100% of the bill
- No budget envelopes: a runaway agent burned $80k last weekend before anyone noticed
- No forecast: CFO can't project next quarter's AI spend within 3× accuracy

Gartner 2026 is publishing "10 Best Practices for Optimizing Generative & Agentic AI Costs" — this is now required reading in every boardroom.

**The budget exists today**. FinOps teams have line items for "cloud cost optimization" that AI spend now falls under. Buying decisions happen in weeks, not quarters.

---

## 2. The Product

LedgerLens gives finance + engineering + product leaders:

- **Tagged cost attribution** — every LLM/tool call tagged with feature, BU, customer, workflow, team
- **Unit economics dashboard** — cost per customer, cost per request, cost per outcome
- **Chargeback reports** — monthly P&L by business unit, ready for finance close
- **Budget envelopes** — hard caps per team/feature/customer with auto-downgrade or deny
- **Spend forecast** — 30/60/90-day projected spend per dimension with confidence intervals
- **Waste heatmaps** — top-10 most expensive features/customers/workflows, rightsizing suggestions
- **Anomaly alerts** — "feature X spent 3× yesterday's baseline in the last hour" → Slack/PagerDuty
- **Model portfolio optimizer** — which requests should drop to mini/haiku/3.5 with no quality loss
- **Cache ROI** — cacheable patterns and $ saved if enabled
- **CFO-ready exports** — CSV/Excel/Parquet + pre-built Power BI / Looker templates

---

## 3. Connector Capability Audit (~90% done)

| Capability | Connector Endpoint | Status |
|---|---|---|
| Per-token metering (LLM) | `billing::record_llm_gateway_usage()` | ✅ |
| Per-tool-call metering | `billing::record_tool_call()` | ✅ |
| Tier enforcement | `EntitlementSet::for_tier()` | ✅ |
| Hard limits + overage | Billing service | ✅ |
| Per-agent cost | `GET /agents/:pid/cost` | ✅ |
| Cost dashboard | `GET /monitor/cost-dashboard` | ✅ |
| Cost center | `GET /monitor/cost-center` | ✅ |
| Cost timeline per agent | `GET /history/agents/:pid/cost-timeline` | ✅ |
| Fleet cost compare | `GET /history/fleet/compare` | ✅ |
| Budget forecast | `GET /insights/budget-forecast/:pid` | ✅ |
| Capacity forecast | `GET /monitor/forecast` | ✅ |
| Usage export | `GET /monitor/usage-export` | ✅ |
| Anomaly detection | `GET /monitor/anomalies/v2` | ✅ |
| Cost by model | `GET /experiments/:id/compare-cost` | ✅ |
| Budget alerts | `GET /monitor/budget-alerts` | ✅ |
| Model rightsizing | `GET /insights/model-recommendation/:pid` | ✅ |
| Stripe billing / portal | Full Stripe integration | ✅ |

**What's new (~10%)**: cost tags (feature/BU/customer/workflow), chargeback reports, budget envelopes per dimension, CFO exports, cache ROI estimator, BI templates.

---

## 4. Architecture

```
┌──────────────────────────────────────────────────────┐
│              LedgerLens UI (browser + CLI)           │
│  Dashboard · Attribution · Forecast · Waste ·        │
│  Chargeback · Budgets · Anomaly Feed · Exports       │
└──────────────────────────┬───────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────┐
│            LedgerLens API Service                    │
│  /costs · /tags · /budgets · /forecast · /chargeback │
│  /anomalies · /waste · /exports · /rightsize         │
└──────────────────────────┬───────────────────────────┘
                           │ HTTP only
┌──────────────────────────▼───────────────────────────┐
│                CONNECTOR (kernel)                    │
│  billing · monitor · insights · history · forecast   │
└──────────────────────────────────────────────────────┘
```

### Ingest model

Every call flowing through Connector's gateway (`/v1/chat/completions`, `/v1/messages`, MCP tool dispatch) already records usage. LedgerLens adds a **tagging header**:

```
X-LedgerLens-Tags: feature=onboarding,bu=marketing,customer=acme_corp,workflow=email_draft
```

Tags propagate to the billing record. Reports aggregate by any tag dimension.

---

## 5. Core Features

### 5.1 Cost Attribution Dashboard
- Pivot by: feature, BU, customer, workflow, team, model, agent, time
- Drill from summary → individual calls
- Time ranges: 1h, 24h, 7d, 30d, QTD, YTD, custom
- Comparison mode: this period vs last period, % delta

### 5.2 Unit Economics
- Per-customer cost + revenue (imported from Stripe/billing system)
- Gross margin per feature
- Cost per outcome (e.g., "cost per successful support ticket resolution")
- Breakeven analysis: "feature X becomes profitable at 12,000 MAUs"

### 5.3 Chargeback Reports
- Monthly P&L by BU or team
- Auto-generated end of billing cycle
- Finance-ready formats: CSV, Excel, Parquet
- Journal entry templates for NetSuite/QuickBooks/Sage

### 5.4 Budget Envelopes
- Scope: per BU, per feature, per customer, per workflow, per agent
- Daily / weekly / monthly / custom caps
- On-breach policies:
  - `alert_only` — notify, continue
  - `downgrade` — auto-switch to cheaper model
  - `hard_stop` — deny requests until reset / approval
  - `cap_and_queue` — hold requests until next period
- Per-role approval to raise caps

### 5.5 Spend Forecast
- 30/60/90-day projections by dimension
- Confidence intervals (p50, p80, p95)
- Seasonality-aware (weekly, monthly patterns)
- Scenario modeling: "what if we roll out feature X to EU?"

### 5.6 Waste Heatmap
Top-10 ranked lists with estimated savings:
- Most expensive agents on oversized models → rightsize recommendations
- Most duplicated prompt contexts → caching opportunities
- Most retried failing requests → stability opportunities
- Most zombie agents with recurring cost → cleanup candidates

### 5.7 Anomaly Feed
- Real-time detection: "feature X spent 3× baseline in last hour"
- Root cause hypothesis (derived from Connector's causal analysis)
- Notification routing: Slack, PagerDuty, Opsgenie, webhook
- Auto-actions: pause agent, downgrade model, escalate

### 5.8 Model Portfolio Optimizer
- Analyze last 30 days of traffic per workflow
- Recommend model mix: "80% of gpt-4o calls in workflow Y can use gpt-4o-mini with no quality loss (judge-eval 0.97 match)"
- Estimated savings: $X/mo
- One-click apply (goes through approval flow if configured)

### 5.9 Cache ROI Estimator
- Identifies repeated prompt patterns
- Estimates cache hit rate + $ saved
- Semantic cache recommendations (similar prompts, different wording)

### 5.10 CFO Exports
- Monthly close package:
  - Total spend by cost center
  - Unit economics rollup
  - Budget variance report
  - Journal entries
- Scheduled delivery: email, S3, Snowflake, BigQuery
- Pre-built BI templates: Power BI, Looker, Tableau, Metabase

---

## 6. New Endpoints (thin layer)

| Endpoint | Purpose | Connector calls behind |
|---|---|---|
| `POST /tags/ingest` | Attach tags to in-flight requests | middleware |
| `GET /costs` | Multi-dimensional cost query | `/monitor/cost-*` + aggregation |
| `GET /costs/unit-economics` | Cost per customer/outcome | billing + external revenue join |
| `GET /chargeback/:period` | Monthly P&L by BU | billing aggregation |
| `POST /budgets` | Create envelope | new Postgres |
| `GET /budgets/status` | Envelope burn rates | billing + envelopes |
| `GET /forecast` | Spend projection by dimension | `/monitor/forecast` + `/insights/budget-forecast` |
| `GET /waste/top` | Waste heatmap | insights aggregation |
| `GET /anomalies/cost` | Cost anomalies | `/monitor/anomalies/v2` filtered |
| `POST /rightsize/apply/:rec_id` | Apply model downgrade | `/insights/apply-fix` |
| `GET /exports/:type` | Generate CFO export | billing + format renderer |

---

## 7. Build Order

### Phase 1 — Attribution + Dashboard (week 1-3)
Goal: show a CFO their AI bill sliced by feature/BU.
- Tag ingest middleware (header-based)
- Tag propagation into billing records (schema extension)
- Cost query API with pivot dimensions
- Dashboard UI with pivot + drill-down
- Basic CSV export

**Ships: first pilot customers. "Show me my AI cost by product feature."**

### Phase 2 — Budgets + Anomalies (week 4-6)
- Budget envelope CRUD (Postgres)
- Enforcement hooks (alert / downgrade / hard-stop)
- Anomaly feed (connected to `/monitor/anomalies/v2`)
- Slack / PagerDuty / webhook notifications

**Ships: Pro tier. First paid conversions.**

### Phase 3 — Forecast + Waste + Rightsize (week 7-9)
- Forecast UI with confidence intervals
- Waste heatmap with top-10 rankings
- Model portfolio optimizer (pulls from Connector insights)
- One-click apply-fix flow

**Ships: Team tier. Expansion sales to pilot customers.**

### Phase 4 — Chargeback + Enterprise Exports (week 10-12)
- Chargeback P&L generator
- Unit economics (requires revenue data import)
- CFO monthly-close package
- BI templates (Power BI, Looker, Tableau, Metabase)
- Scheduled exports to Snowflake/BigQuery/S3

**Ships: Enterprise tier. Finance-team signoff.**

**Total: 12 weeks / 1-2 engineers.**

---

## 8. Competitive Position

| Feature | LedgerLens | Vantage | CloudZero | Revenium | AI Vyuh |
|---|---|---|---|---|---|
| Generic cloud cost | partial | ✅ | ✅ | partial | ○ |
| **AI-native attribution** | ✅ | partial | partial | ✅ | ✅ |
| **Per-feature / per-customer tags** | ✅ | ○ | partial | ✅ | ✅ |
| **Per-workflow / per-agent** | ✅ | ○ | ○ | ○ | ○ |
| **Unit economics (cost × revenue)** | ✅ | partial | partial | partial | ○ |
| **Chargeback P&L generation** | ✅ | partial | ✅ | partial | ○ |
| **Budget envelopes w/ enforcement** | ✅ | partial | ○ | ✅ | partial |
| **Hard-stop / auto-downgrade on breach** | ✅ | ○ | ○ | ○ | ○ |
| Forecast w/ confidence intervals | ✅ | ✅ | ✅ | partial | ○ |
| **Model rightsizing (from judge-eval)** | ✅ | ○ | ○ | ○ | ○ |
| **Cache ROI estimator** | ✅ | ○ | ○ | ○ | ○ |
| Cost anomaly detection | ✅ | ✅ | ✅ | ✅ | partial |
| **Causal analysis (root cause)** | ✅ | ○ | ○ | ○ | ○ |
| BI templates | ✅ | partial | ✅ | ○ | ○ |
| **CID-chained audit of spend** | ✅ | ○ | ○ | ○ | ○ |
| Self-hosted | ✅ | ○ | ○ | ○ | ○ |

**Moat vs general cloud tools (Vantage, CloudZero)**: agent-native — they understand per-call, per-workflow, per-agent structure; general tools don't.

**Moat vs AI-native newcomers (Revenium, AI Vyuh)**: enforcement (auto-downgrade, hard-stop) + rightsizing with judge-eval + CID-chained audit. They observe; LedgerLens acts.

---

## 9. Pricing

| Tier | Price | Includes |
|---|---|---|
| Free | $0 | 1 tenant, 7-day retention, dashboard only |
| Pro | $99/mo | 5 tags, 90-day retention, anomaly alerts, budget envelopes |
| Team | $499/mo | Unlimited tags, 1-yr retention, forecast, rightsizing, cache ROI |
| Enterprise | Custom (typ. $2k-$8k/mo) | On-prem, SSO, chargeback reports, BI templates, SLA |

**Value framing**: Team tier pays for itself if customer saves >$500/mo from rightsizing (typical is $2k-$20k/mo on $100k+ monthly AI spend).

---

## 10. Go-To-Market

### Buyer
**Primary**: Head of FinOps / Director of Cloud Cost. Has budget line for cloud optimization. AI now in scope.
**Secondary**: CTO / VP Engineering. Owns AI spend, hates surprises, wants unit economics.
**Champion**: Platform engineer who just got paged for $80k runaway agent spend.

### Wedge
Free tier attribution demo:
1. Customer routes 7 days of traffic through LedgerLens
2. Day 8: "Here's your AI spend sliced by feature/BU. This one feature is 60% of your bill."
3. CFO sees dashboard in Monday exec review → conversation with finance procurement → contract in 3 weeks.

### Channel
- Product-led self-serve (Free + Pro)
- Sales-led for Team + Enterprise
- FinOps Foundation sponsorship / talks
- Integration partners: Stripe, Snowflake, Databricks, Power BI marketplace
- Cloud marketplaces (AWS, GCP, Azure) for enterprise procurement

---

## 11. Positioning

> **LedgerLens is AI FinOps done right. Tag every AI call. Attribute every dollar. Forecast the next quarter. Chargeback by BU. Stop runaway spend automatically — all in one platform, cryptographically audited.**

> **See your AI bill. Slice it any way. Stop the leaks.**
