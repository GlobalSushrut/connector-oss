# Connector OS — Enhanced Deployment & Product Readiness Plan

## Executive Summary

| Component | Status | Production Ready | Notes |
|-----------|--------|------------------|-------|
| **DevGuard** | ✅ Implemented | Yes | Full CLI, git hooks, dashboard, policy engine |
| **TraceTramp** | ⚠️ Partial | No | Code exists, needs testing & hardening |
| **WitnessCtl** | ⚠️ Partial | No | Code exists, capture/proxy works, compliance exports WIP |
| **Playground** | ✅ Ready | Yes | Docker Compose, 90-min sessions, stub LLM |
| **License Server** | ✅ Ready | Yes | PostgreSQL, Stripe, SendGrid, Ed25519 signing |
| **Admin Panel** | ✅ Ready | Yes | Leptos/WASM, all 6 pages functional |
| **Pilot Grants** | ✅ Ready | Yes | API + UI, seat-based, time-limited |

---

## Part I: Product Usage Analysis

### 1. DevGuard — Developer Workflow Integration

**What it actually does:**
DevGuard is a CLI application (not just a plugin) that intercepts git operations and IDE interactions to enforce policies before code leaves the developer's machine.

**User Journey — Developer (Local):**

```bash
# 1. Install
$ curl -sSL https://cdn.cnktros.com/releases/latest/install.sh | bash
$ devguard doctor
[✓] DevGuard binary
[✓] Exec guard library
[✓] License valid (Community)

# 2. Initialize in project
$ cd ~/projects/myapp
$ devguard init
Created devguard.yaml

# 3. Start governed session
$ devguard start
[devguard] Dashboard: http://localhost:7744
[devguard] Git hooks installed
[devguard] Watching 47 files
```

**Daily Workflow:**
1. Developer opens project → DevGuard auto-starts via shell hook
2. Makes code changes → File watcher tracks all edits
3. Attempts `git commit` → Pre-commit hook invokes `devguard check`
4. Policy evaluation:
   - Secret scan: No API keys detected → ✓
   - File boundaries: Writing to `src/` only → ✓
   - Test verification: `cargo test` passes → ✓
   - Commit allowed → Receipt generated
5. Push attempted → HITL approval required → Manager gets Slack notification → Approves → Push proceeds

**Dashboard View (`:7744`):**
- Live session status (working / idle / blocked)
- Last 10 actions with receipts
- Blocked actions queue
- Policy coverage percentage
- Token budget remaining

**Production Deployment Considerations:**
```yaml
# devguard.yaml for production teams
identity:
  provider: github
  require_auth: true
  org: mycompany

approvals:
  write_protected: { require: code_owner, quorum: 1 }
  deploy: { require: [tech_lead, sre], quorum: 1 }

git:
  require_pr: true
  no_force_push: true
  require_linear_history: true

secrets:
  detect_and_redact: true
  fail_on_leak: true  # HARD block, not just warning
```

**Key Deployment Risk:**
DevGuard requires `LD_PRELOAD` for exec guard in cage mode. This may conflict with:
- macOS SIP (System Integrity Protection)
- Corporate endpoint security tools
- Containerized development environments

**Mitigation:**
- Provide `devguard cage start --soft` mode (git hooks only, no LD_PRELOAD)
- Document enterprise rollout: pilot → team → org
- Support SSH remote development (exec guard disabled on remote)

---

### 2. TraceTramp — LLM Traffic Governance (NOT PRODUCTION READY)

**Current State:**
- Code exists: 41 source files, Axum server, PostgreSQL migrations
- Data plane (:9741) and Management plane (:9742) defined
- Provider implementations: OpenAI, Anthropic, Azure, Ollama stubs
- Budget tables, policy tables, decision tree logic present

**What's Missing for Production:**
1. **No tested cage route** — The `ANY /cage/:sha_address/*path` route exists but hasn't been load-tested
2. **Redis dependency** — Used for rate limiting but no Redis in deployment config
3. **Provider credential handling** — unclear how tenant-specific provider keys are injected
4. **No TUI dashboard** — README mentions TUI but `tracetramp tui` command not found
5. **HITL hold queue** — `approval_queue` table exists but no documented review flow

**User Journey (Vision vs Reality):**

```bash
# Vision:
$ tracetramp start
[tracetramp] Data plane: :9741
[tracetramp] Management plane: :9742
[tracetramp] TUI: http://localhost:9743

# Reality - currently requires manual cargo run:
$ cargo run --manifest-path plugins/tracetramp/Cargo.toml
# Needs DATABASE_URL, REDIS_URL env vars set
```

**Integration Pattern (When Ready):**
```python
# Before: Direct OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# After: Through TraceTramp
client = OpenAI(
    base_url="http://localhost:9741/cage/tenant-sha",
    api_key="tt-api-key-from-connector"
)
# All requests now metered, policy-checked, traced
```

**Deployment Recommendation:**
**DO NOT** include TraceTramp in v1.0 launch. Market as "coming Q3" while DevGuard drives initial adoption.

---

### 3. WitnessCtl — Audit Evidence (NOT PRODUCTION READY)

**Current State:**
- 18 source modules, Axum server, 16 migrations
- Proxy engine, capture engine, receipt chain, compliance export framework
- PDF export using `connector-report-pdf` crate

**What's Missing for Production:**
1. **Chain verification** — HMAC receipts exist but verification endpoint untested
2. **Custody quorum** — SQL tables for custody nodes, but no custody node implementation
3. **Compliance frameworks** — Framework definitions exist (SOC2, ISO27001) but mapping logic incomplete
4. **Seal creates local file** — `witnessctl seal` creates DB record but no `.witness` bundle file
5. **PII redaction** — Detection exists but redaction preview not wired to TUI

**User Journey (Vision):**
```bash
$ witnessctl start --name "q1-audit"
[witnessctl] Proxy: http://localhost:7443/witness/wit-xxx
[witnessctl] Route your API calls through this proxy

$ export OPENAI_BASE_URL="http://localhost:7443/witness/wit-xxx"
$ python my_agent.py  # All calls captured with receipts

$ witnessctl seal wit-xxx
[witnessctl] ✓ Sealed: ~/Downloads/witnessctl-wit-xxx.witness

$ witnessctl export wit-xxx --format pdf --framework soc2
[witnessctl] ✓ Exported: witnessctl-soc2-q1.pdf (auditor-ready)
```

**Deployment Recommendation:**
Include in launch as "Preview / Beta" feature. Works for single-node capture, but don't promise multi-witness custody chains or compliance exports yet.

---

### 4. Playground — Hosted Trial Experience

**Current Implementation:**
```yaml
# docker-compose.playground.yml
services:
  connector-playground:
    environment:
      CONNECTOR_PRESET: playground
      CONNECTOR_PLAYGROUND_SESSION_TTL_SECS: "5400"  # 90 min
      CONNECTOR_PLAYGROUND_MAX_SESSIONS: "50"
      CONNECTOR_PLAYGROUND_MAX_AGENTS: "5"
      CONNECTOR_PLAYGROUND_TOKEN_BUDGET: "100000"
      CONNECTOR_LLM_STUB: "1"  # No real LLM calls = no API costs
```

**User Flow:**
1. User visits `try.cnktros.com`
2. Caddy routes to playground container
3. Playground creates session namespace
4. Web terminal (xterm.js) spawns with DevGuard pre-installed
5. User runs `devguard cage start --mode demo`
6. Dashboard opens in new tab showing live governance
7. After 90 min or 100K tokens → Session terminated, data purged

**Resource Limits (Per Session):**
| Limit | Value | Purpose |
|-------|-------|---------|
| Session TTL | 90 min | Cost control |
| Max Agents | 5 | Prevent fork bombs |
| Token Budget | 100K | LLM spend cap |
| Idle Timeout | 15 min | Resource cleanup |

**Deployment Considerations:**
- **Memory**: 2GB per playground node supports ~50 concurrent sessions
- **Storage**: No persistent storage (ephemeral containers)
- **LLM Costs**: `CONNECTOR_LLM_STUB=1` means zero API costs for trial
- **Security**: Namespaced containers, no network egress except to license server

---

### 5. Pilot Grants — Early Access Management

**Implementation Status:** ✅ Complete

**API Endpoints:**
```rust
// platform/licensing/src/pilot_api.rs
POST   /api/v1/admin/pilots          // Create grant
GET    /api/v1/admin/pilots          // List all
GET    /api/v1/admin/pilots/:id      // Get specific
DELETE /api/v1/admin/pilots/:id      // Expire
POST   /api/v1/admin/pilots/:id/revoke  // Revoke with reason
```

**Admin UI (`admin.cnktros.com/pilots`):**
- Table of all pilot grants
- Create form: Customer ID, Seats, Duration, Tier Override, Note
- Revoke action with reason logging
- Auto-expiry (cron job marks expired grants)

**Grant Structure:**
```rust
pub struct PilotGrant {
    pub grant_id: String,           // pilot_xxx
    pub customer_id: String,        // cus_xxx (Stripe)
    pub granted_by: String,         // admin email
    pub created_at: String,
    pub expires_at: String,         // 30/60/90 days
    pub tier_override: Option<String>,  // "professional" | "enterprise"
    pub agent_limit_override: Option<u32>,
    pub packet_limit_override: Option<u64>,
    pub features_override: Vec<String>,
    pub reason: String,
    pub status: String,             // "active" | "expired" | "revoked"
}
```

**Usage Flow:**
1. Sales team gets enterprise lead
2. Admin creates pilot grant: 10 seats, 60 days, Enterprise tier
3. Customer receives email with pilot activation link
4. Customer activates → License issued with pilot entitlements
5. At 60 days: Auto-expires, customer prompted to purchase

**Deployment Checklist:**
- [ ] SendGrid configured for pilot invitation emails
- [ ] Cron job for daily expiry checks
- [ ] Slack webhook for new pilot notifications

---

### 6. Admin Panel — Control Plane Status

**Implementation Status:** ✅ System Worthy

**Architecture:**
- Framework: Leptos (Rust WASM)
- Hosting: Vercel (static files)
- API: Calls `api.cnktros.com` (license server)

**Pages & Status:**

| Page | File | Status | Features |
|------|------|--------|----------|
| Login | `login.rs` | ✅ | Admin key auth, session storage |
| Dashboard | `dashboard.rs` | ✅ | 4 KPI cards, MRR display, tier breakdown |
| Keys | `keys.rs` | ✅ | Issue/revoke table, tier badges, copy-to-clipboard |
| Payments | `payments.rs` | ✅ | Transactions list, invoice PDF download |
| Dunning | `dunning.rs` | ✅ | Health cards (active/past-due/degraded/suspended), actions |
| Surveillance | `surveillance.rs` | ✅ | Fleet stats, instances table, event log toggle |
| Pilots | `pilots.rs` | ✅ | Create/revoke form, seat/duration config |
| Revenue | `revenue.rs` | ✅ | MRR/ARR charts (placeholder for real data) |
| Customers | `customers.rs` | ✅ | Customer list, search, detail view |

**Navigation (Sidebar):**
```
Overview
  Dashboard
Customers
  All Customers
  Pilot Grants
Finance
  Revenue
  Payments
  Dunning
Fleet
  Keys
  Surveillance
```

**Security:**
- Protected by `CONNECTOR_LICENSE_ADMIN_KEY`
- Cloudflare WAF: Admin IP restriction
- No session persistence (localStorage only, cleared on logout)

**Deployment:**
```bash
cd platform/ui-leptos/admin
vercel --prod
# Sets admin.cnktros.com → Vercel
```

**Known Limitations:**
1. No RBAC within admin panel (single admin key)
2. No audit log of admin actions (who revoked which key?)
3. Real-time updates require page refresh (no WebSocket)
4. Revenue charts are static (need Chart.js or similar integration)

**Mitigation for Launch:**
- Document: "Single admin access for v1.0"
- Add admin action logging to database
- Accept manual refresh for now

---

## Part II: Revised Deployment Strategy

### Phase 1: Foundation (Week 1)

**Goal:** License server + Admin panel + Basic playground

```bash
# 1. Database
# Neon Postgres already configured from DEPLOYMENT.md

# 2. License Server
docker compose -f docker-compose.control-plane.yml up license

# 3. Verify
curl https://api.cnktros.com/health
# Expected: db_ok: true, keys_loaded: 1

# 4. Admin UI
cd platform/ui-leptos/admin && vercel --prod

# 5. Verify
curl https://admin.cnktros.com
# Expected: Login page loads
```

**Success Criteria:**
- Can issue license keys via admin panel
- Stripe webhooks processed
- Customer portal loads at `cnktros.com`

---

### Phase 2: Playground Launch (Week 2)

**Goal:** Hosted trial experience driving DevGuard adoption

```bash
# 1. Deploy playground
docker compose -f docker-compose.control-plane.yml up playground

# 2. Verify session creation
curl -X POST https://try.cnktros.com/api/v1/playground/session
# Expected: { session_id: "ps_xxx", ws_url: "wss://...", ttl: 5400 }
```

**User Flow Verification:**
1. Visit `try.cnktros.com` → Terminal appears
2. Run `devguard cage start` → Dashboard opens
3. Make test commit → Appears in dashboard
4. Wait 90 min → Session auto-terminates

**Marketing Integration:**
- Landing page: "Try DevGuard in 15 seconds"
- No signup required (anonymous sessions)
- Exit CTA: "Install locally" with copy-paste command

---

### Phase 3: DevGuard Distribution (Week 3)

**Goal:** One-command install for local usage

```bash
# Release tarball structure
connector-os-0.1.0-linux-amd64.tar.gz
├── bin/devguard
├── bin/connectorctl
├── lib/libdevguard_exec_guard.so
├── share/config/devguard.yaml.example
└── install.sh

# CDN path
https://cdn.cnktros.com/releases/latest/install.sh
```

**Install Script Flow:**
1. Detect OS/arch (linux-amd64, linux-arm64, darwin-amd64, darwin-arm64)
2. Download matching tarball
3. Extract to `/opt/connector-os/`
4. Symlink `devguard` → `/usr/local/bin/`
5. Run `devguard doctor` verification
6. Print: "Run 'devguard init' in your project"

**Verification:**
```bash
# Test on clean Ubuntu VM
curl -sSL https://cdn.cnktros.com/releases/latest/install.sh | bash
devguard doctor  # All checks pass
devguard init    # Creates devguard.yaml
devguard start   # Dashboard available
```

---

### Phase 4: Pilot Program (Week 4)

**Goal:** Managed early access for enterprise prospects

**Admin Workflow:**
1. Sales qualifies lead
2. Admin creates pilot grant via `admin.cnktros.com/pilots`
   - Customer ID: `enterprise-prospect-1`
   - Seats: 25
   - Duration: 60 days
   - Tier: Enterprise
   - Note: "Acme Corp evaluation via Sarah (sales)"
3. System sends email with pilot activation link
4. Customer activates → License issued with:
   - `tier: enterprise`
   - `max_agents: 100`
   - `expires_at: +60 days`
   - `features: [team_mode, priority_support, audit_export]`

**Tracking:**
- Daily Slack notification: "Pilot expiring in 7 days: Acme Corp"
- Conversion tracking: Pilot → Paid conversion rate

---

### Phase 5: TraceTramp Beta (Week 8-12)

**Goal:** Selective availability for design partners

**Criteria for Launch:**
- [ ] Cage route load tested (1000 req/sec)
- [ ] Redis removed or made optional (simplify deployment)
- [ ] TUI dashboard functional (`tracetramp tui`)
- [ ] Provider credential injection documented
- [ ] 3 design partners successfully using in production

**Deployment Pattern:**
```bash
# NOT for general users yet — manual install only
cargo install --path plugins/tracetramp
tracetramp --config tracetramp.yaml
```

---

### Phase 6: WitnessCtl Beta (Week 12-16)

**Goal:** Compliance-ready audit capture

**Criteria for Launch:**
- [ ] `.witness` bundle file generation
- [ ] Chain verification CLI (`witnessctl verify`)
- [ ] SOC2 control mapping complete
- [ ] PDF export with auditor branding
- [ ] 1 compliance team successfully using

---

## Part III: Risk Assessment & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| DevGuard LD_PRELOAD conflicts with macOS SIP | High | Medium | Document `--soft` mode, provide VM alternative |
| Playground session escapes container | Low | Critical | seccomp profile, no --privileged, readonly rootfs |
| License server key volume lost | Low | Critical | Automated backups, redundant key shares |
| Stripe webhook delivery fails | Medium | Medium | Idempotent handlers, manual sync dashboard |
| Admin panel XSS | Low | High | CSP headers, input sanitization, WASM sandbox |
| TraceTramp memory leak under load | Medium | High | Load testing before public, resource limits |

---

## Part IV: Success Metrics

**Week 1-4 (Launch):**
- 100 playground sessions created
- 50 devguard installations
- 10 pilot grants created
- 5 paid conversions

**Month 2-3:**
- 1000 active DevGuard licenses
- 100 pilot-to-paid conversions (10% rate)
- $10K MRR
- 99.9% license server uptime

**Month 6:**
- TraceTramp public beta (100 users)
- WitnessCtl SOC2 certified
- $50K MRR
- Self-serve Enterprise tier

---

*This plan prioritizes proven components (DevGuard, Playground, License, Admin) while setting clear criteria for beta features (TraceTramp, WitnessCtl).*
