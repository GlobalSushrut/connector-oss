# Connector OS — Deployment Plan
## Stack: Fly.io · Neon Postgres · Vercel · Cloudflare

---

## 0. Architecture Overview

```
Internet
  │
  ▼
Cloudflare (DNS proxy, WAF, DDoS, CDN)
  ├─ cnktros.com           → Vercel  (marketing static site — already live)
  ├─ admin.cnktros.com     → Vercel  (admin SPA — Leptos/WASM)
  ├─ api.cnktros.com       → Fly.io  connector-license  (license server)
  ├─ portal.cnktros.com    → Fly.io  connector-license  (customer portal SPA)
  └─ try.cnktros.com       → Fly.io  connector-playground (hosted trial)
                                       │
                                       ▼
                               Neon Postgres (serverless, auto-scale)
```

| Service            | Host          | Cost (free→paid)     |
|--------------------|---------------|----------------------|
| Marketing site     | Vercel        | Free                 |
| Admin UI           | Vercel        | Free                 |
| License server     | Fly.io        | ~$5/mo (shared-cpu)  |
| Playground node    | Fly.io        | ~$10/mo (2x shared)  |
| Postgres           | Neon          | Free → $19/mo        |
| Ed25519 keys vol.  | Fly volume    | ~$0.15/GB/mo         |
| DNS + WAF          | Cloudflare    | Free                 |
| **Total launch**   |               | **~$0–$15/mo**       |

---

## Part I: Step-by-Step Deployment Guide

### Phase 1: Infrastructure Setup (Day 1)

#### 1.1 Prerequisites Installation

```bash
# Fly CLI — for deploying license server and playground
curl -L https://fly.io/install.sh | sh
fly auth login

# Vercel CLI — for deploying admin UI
npm i -g vercel
vercel login

# Verify installations
fly version  # should show v0.x.x
vercel --version  # should show v30.x.x
```

#### 1.2 Database Setup (Neon Postgres — Recommended)

```bash
# 1. Create account at https://neon.tech (GitHub SSO supported)
# 2. Create new project: "connector-prod"
# 3. Select region: "AWS US East (N. Virginia)" for lowest latency
# 4. Copy the connection string from the "Connection Details" panel
```

**Connection string format:**
```
postgresql://connector_owner:password@ep-xxx.us-east-2.aws.neon.tech/connector?sslmode=require
```

**Store in your password manager under:** `Connector OS / Neon Database URL`

#### 1.3 First-Time Fly.io Setup

```bash
cd platform/deploy

# Run the automated init script (creates apps, volumes, secrets structure)
./scripts/fly-deploy.sh init

# Expected output:
# [init] Creating Fly.io apps...
# ✓ Created app: connector-license
# ✓ Created app: connector-playground
# ✓ Created volume: connector_keys (1GB) in iad
# [init] Done. Now set secrets with: fly secrets set ...
```

**What the init script does:**
- Creates `connector-license` app (license server + portal)
- Creates `connector-playground` app (hosted trial nodes)
- Creates 1GB volume `connector_keys` mounted at `/data/keys/`
- Generates fly.toml configs from templates

#### 1.4 Critical Secrets Configuration

**Generate secure keys:**
```bash
# Admin key for accessing /admin routes (32-byte hex)
export ADMIN_KEY=$(openssl rand -hex 32)
echo "Admin key: $ADMIN_KEY"  # Save this immediately

# License signing key seed (backup this value)
export LICENSE_SEED=$(openssl rand -hex 32)
```

**Set all secrets on license app:**
```bash
fly secrets set -a connector-license \
  DATABASE_URL="postgresql://..." \
  CONNECTOR_LICENSE_ADMIN_KEY="$ADMIN_KEY" \
  CONNECTOR_LICENSE_SEED="$LICENSE_SEED" \
  STRIPE_SECRET_KEY="sk_live_..." \
  STRIPE_WEBHOOK_SECRET="whsec_..." \
  STRIPE_PRICE_COMMUNITY="price_..." \
  STRIPE_PRICE_STARTUP="price_..." \
  STRIPE_PRICE_PROFESSIONAL="price_..." \
  STRIPE_PRICE_ENTERPRISE="price_..." \
  SENDGRID_API_KEY="SG...."
```

**Set secrets on playground app:**
```bash
fly secrets set -a connector-playground \
  DATABASE_URL="postgresql://..." \
  CONNECTOR_PLAYGROUND_SECRET="$(openssl rand -hex 32)" \
  CONNECTOR_LICENSE_URL="https://api.cnktros.com"
```

---

### Phase 2: Deploy Services (Day 1-2)

#### 2.1 Deploy License Server

```bash
# Build and deploy (takes ~3-5 minutes for Rust compilation)
./scripts/fly-deploy.sh license

# Or manually:
docker build -f Dockerfile.license -t connector-license .
fly deploy -c fly.license.toml --dockerfile Dockerfile.license
```

**Verify deployment:**
```bash
curl https://api.cnktros.com/health
# Expected response:
# {
#   "status": "ok",
#   "service": "connector-license-server",
#   "version": "0.1.0",
#   "db_ok": true,
#   "keys_loaded": 1,
#   "active_keys": 0,
#   "customers": 0,
#   "instances": 0,
#   "uptime_secs": 45
# }
```

#### 2.2 Deploy Playground Node

```bash
./scripts/fly-deploy.sh playground

# Verify
curl https://try.cnktros.com/health
# Expected: {"status":"ok","playground":true,"nodes_available":3}
```

#### 2.3 Deploy Admin UI to Vercel

```bash
cd platform/ui-leptos/admin

# First deploy
vercel --prod

# Subsequent deploys
vercel --prod
```

**Vercel Project Settings:**
- Framework: **Other**
- Build Command: `trunk build --release`
- Output Directory: `dist`
- Install Command: (handled by vercel.json)

**Environment Variables:**
```
VITE_API_BASE_URL = https://api.cnktros.com
```

---

### Phase 3: Cloudflare Configuration (Day 2)

#### 3.1 DNS Records Setup

| Type  | Name           | Target                              | Proxy |
|-------|----------------|-------------------------------------|-------|
| CNAME | @              | cname.vercel-dns.com                | ✓     |
| CNAME | www            | cname.vercel-dns.com                | ✓     |
| CNAME | admin          | cname.vercel-dns.com                | ✓     |
| CNAME | api            | connector-license.fly.dev           | ✓     |
| CNAME | portal         | connector-license.fly.dev           | ✓     |
| CNAME | try            | connector-playground.fly.dev        | ✓     |

**In Cloudflare Dashboard:**
1. Go to **DNS** → **Records**
2. Add each CNAME above
3. Ensure orange cloud (proxied) is ON for all
4. Wait 30-60 seconds for propagation

#### 3.2 SSL/TLS Configuration

**SSL/TLS → Overview:**
- Encryption mode: **Full (strict)**
- Minimum TLS Version: **1.2**

**SSL/TLS → Edge Certificates:**
- Always Use HTTPS: **ON**
- Automatic HTTPS Rewrites: **ON**
- HSTS: Enable with max-age 1 year, include subdomains

#### 3.3 WAF Rules (Security)

**Security → WAF → Custom Rules:**

**Rule 1: Admin IP Restriction**
```
(http.request.uri.path contains "/admin") and 
(not ip.src in {YOUR_OFFICE_IP/32 YOUR_HOME_IP/32})
→ Action: Block
```

**Rule 2: Rate Limit Activations**
```
(http.request.uri.path eq "/api/v1/activate")
→ Action: Rate limit — 20 requests per 60 seconds
```

**Rule 3: Rate Limit RPC Auth**
```
(http.request.uri.path eq "/rpc/v1/auth")
→ Action: Rate limit — 30 requests per 60 seconds
```

---

### Phase 4: Stripe Integration (Day 2)

#### 4.1 Webhook Endpoint Setup

**Stripe Dashboard → Developers → Webhooks → Add endpoint:**

```
Endpoint URL: https://api.cnktros.com/webhooks/stripe
```

**Select events:**
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_succeeded`
- `invoice.payment_failed`

**Copy the signing secret:**
```bash
fly secrets set -a connector-license STRIPE_WEBHOOK_SECRET="whsec_xxxxx"
```

#### 4.2 Product/Price Setup

**Create products in Stripe:**

| Product | Price ID | Amount |
|---------|----------|--------|
| Community | `price_xxx` | $0 (free tier marker) |
| Startup | `price_xxx` | $29/mo |
| Professional | `price_xxx` | $99/mo |
| Enterprise | `price_xxx` | $499/mo |

Store each price ID in secrets as shown in Phase 1.4.

---

### Phase 5: Custom Domain Certificates (Day 3)

```bash
# Issue certificates for custom domains
fly certs add api.cnktros.com -a connector-license
fly certs add portal.cnktros.com -a connector-license
fly certs add try.cnktros.com -a connector-playground

# Check certificate status (takes 1-2 minutes)
fly certs show api.cnktros.com -a connector-license
# Should show: Status = Ready
```

---

### Phase 6: Release Tar Distribution (Day 3)

#### 6.1 Building Release Tarballs

```bash
# Full release build for all platforms
cd /home/umesh/Projects/connector-private
make release

# Or build specific targets:
make release-linux-amd64
make release-linux-arm64
make release-darwin-amd64
make release-darwin-arm64
```

**Output location:** `target/release/connector-os-{version}-{target}.tar.gz`

#### 6.2 Tar Contents

Each release tar contains:

```
connector-os/
├── bin/
│   ├── devguard              # CLI governance plugin
│   ├── tracetramp            # Runtime proxy & control plane
│   ├── witnessctl            # API witness & evidence capture
│   ├── conductor             # Service mesh (future)
│   ├── agentloop             # Agent orchestration (future)
│   └── connectorctl          # Admin CLI
├── lib/
│   └── libdevguard_exec_guard.so  # LD_PRELOAD exec guard
├── share/
│   ├── config/
│   │   ├── devguard.yaml.example
│   │   ├── tracetramp.yaml.example
│   │   └── witnessctl.yaml.example
│   └── docs/
│       └── README.md
└── install.sh                # One-command installer
```

#### 6.3 Distribution Channels

**Direct Download:**
```bash
curl -sSL https://cdn.cnktros.com/releases/latest/install.sh | bash
```

**Versioned releases:**
```bash
curl -sSL https://cdn.cnktros.com/releases/0.1.0/install.sh | bash
```

**Manual download:**
```bash
wget https://cdn.cnktros.com/releases/0.1.0/connector-os-0.1.0-linux-amd64.tar.gz
tar -xzf connector-os-0.1.0-linux-amd64.tar.gz
sudo ./connector-os/install.sh
```

#### 6.4 Installer Behavior

The `install.sh` script:
1. Detects OS/architecture
2. Downloads appropriate tarball
3. Extracts to `/opt/connector-os/`
4. Creates symlinks in `/usr/local/bin/`
5. Runs `devguard doctor` to verify installation
6. Prints next steps and quickstart URL

---

### Phase 7: Monitoring & Backups (Day 3-4)

#### 7.1 UptimeRobot Setup

1. Create free account at https://uptimerobot.com
2. Add monitors:
   - `https://api.cnktros.com/health` (5 min interval)
   - `https://try.cnktros.com/health` (5 min interval)
   - `https://admin.cnktros.com` (5 min interval)
3. Configure alert channels (email, Slack, PagerDuty)

#### 7.2 Database Backups

**Automated Neon backups:**
- Daily snapshots (7-day retention free tier)
- Point-in-time recovery (paid tiers)

**Manual backup to R2:**
```bash
# Set once
export CF_ACCOUNT_ID="xxx"
export CF_R2_BUCKET="connector-backups"
export CF_ACCESS_KEY_ID="xxx"
export CF_SECRET_ACCESS_KEY="xxx"

# Run backup
./scripts/backup-db.sh
```

**Ed25519 key backup (CRITICAL):**
```bash
# Download keys from Fly volume
fly sftp get /data/keys/ ./keys-backup/ -a connector-license

# Store in password manager + offline backup
# These keys sign all licenses — losing them invalidates all customer licenses
```

---

### Phase 8: Launch Checklist

Before announcing:

- [ ] All CNAMEs resolving correctly (`dig api.cnktros.com`)
- [ ] SSL certificates valid (no browser warnings)
- [ ] `/health` endpoints returning `db_ok: true`
- [ ] Stripe webhook test events processed successfully
- [ ] Admin UI login works with admin key
- [ ] Playground node spawning sessions correctly
- [ ] WAF blocking `/admin` from non-authorized IPs
- [ ] Rate limiting active on activation endpoint
- [ ] Release tar downloads working from CDN
- [ ] Install script tested on clean Ubuntu/macOS VM
- [ ] Documentation site linked from marketing page
- [ ] Support email configured (support@cnktros.com)

---

## Part II: User Experience — How People Use Connector OS

### Story 1: Sarah (Startup Developer) — First Contact via Playground

**9:00 AM — Discovery**
Sarah sees a tweet about Connector OS and clicks `try.cnktros.com`. She's immediately dropped into a terminal session without signing up.

**9:02 AM — First Command**
```bash
# The playground shows a welcome banner:
# "Welcome to Connector OS Playground — 15 minutes remaining"
# "Try: devguard cage start --mode demo"

$ devguard cage start --mode demo
[devguard] Starting governed session in demo mode...
[devguard] Dashboard: http://localhost:7744
[devguard] Status API: http://127.0.0.1:7788/devguard/status
[devguard] ✓ Cage active — all git commits now governed
```

**9:05 AM — Understanding DevGuard**
Sarah opens the dashboard at `:7744` in her browser. She sees:
- **Live Monitor**: Shows her current working state, last action, blocked action count
- **Session Health**: Heartbeat timestamp confirms DevGuard is watching
- **Policy Summary**: Lists the default policies (no secrets in commits, no force-push to main)

She makes a test commit and sees it appear in the dashboard with a green checkmark.

**9:08 AM — Experiencing Enforcement**
Sarah tries to simulate a policy violation:
```bash
$ echo "API_KEY=sk-live-123456" > secrets.txt
$ git add secrets.txt && git commit -m "add api key"
[POLICY BLOCKED] Detected potential secret in commit
[devguard] Commit blocked. Dashboard: http://localhost:7744
```

In the dashboard, she sees the blocked action with:
- Policy that triggered: `no-secrets-in-commits`
- File: `secrets.txt`
- Line preview: `API_KEY=sk-****-******` (redacted)
- Action: Block with reason "Credential detected"

**9:10 AM — Understanding the Value**
Sarah realizes this prevents accidents. She clicks "Get Community License" in the dashboard, enters her email, and receives a license key instantly.

**9:12 AM — Installing Locally**
She downloads the release tar:
```bash
curl -sSL https://cdn.cnktros.com/releases/latest/install.sh | bash
# [install] Downloading connector-os-0.1.0-darwin-arm64.tar.gz...
# [install] Extracting to /opt/connector-os/...
# [install] Creating symlinks...
# [install] ✓ Connector OS installed
# [install] Run 'devguard doctor' to verify

$ devguard doctor
[✓] DevGuard binary: /usr/local/bin/devguard
[✓] Exec guard: /opt/connector-os/lib/libdevguard_exec_guard.so
[✓] Config directory: ~/.config/devguard/
[✓] License: Community (valid)
[✓] Connector reachability: https://api.cnktros.com (45ms)
```

**Outcome**: Sarah is now a Community tier user with DevGuard protecting her local repositories.

---

### Story 2: Marcus (Platform Engineer) — TraceTramp for LLM Governance

**10:00 AM — The Problem**
Marcus manages AI infrastructure at a mid-size company. Engineers are calling OpenAI directly with no visibility into spend, no policy enforcement, and no audit trail.

**10:15 AM — Finding TraceTramp**
Marcus discovers TraceTramp on the Connector OS docs. He reads:
> "Drop one cage URL into your app and immediately see enforceable decisions, holds, budgets, and quarantines."

**10:30 AM — Installation**
```bash
$ curl -sSL https://cdn.cnktros.com/releases/latest/install.sh | bash
$ tracetramp doctor
[✓] TraceTramp binary
[✓] Database connection
[✓] Redis connection
[✓] Connector kernel reachable
[✓] License: valid
```

**10:45 AM — Configuration**
Marcus creates `tracetramp.yaml`:
```yaml
# Provider setup
default_provider: openai
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    models: [gpt-4o, gpt-4o-mini]
  
# Budget enforcement  
budgets:
  default_monthly: 500.00
  per_tenant:
    engineering: 2000.00
    
# Policies
policies:
  - name: no-pii-in-prompts
    action: block
    condition: detect_pii = true
  - name: high-cost-model-approval
    action: hold
    condition: model = "gpt-4o" and estimated_cost > 0.50
```

**11:00 AM — Integration**
Marcus updates the company's AI client configuration:
```python
# Before:
# OPENAI_BASE_URL = "https://api.openai.com/v1"

# After:
OPENAI_BASE_URL = "http://localhost:9741/cage/prod-sha256"
OPENAI_API_KEY = "tt-tenant-engineering-key"  # TraceTramp key
```

**11:15 AM — First Protected Request**
An engineer runs a prompt:
```python
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Review this code: ..."}]
)
```

TraceTramp intercepts the request:
1. **Metering**: Tracks tokens, cost attribution to `engineering` tenant
2. **Policy Check**: Verifies no PII detected, budget under limit
3. **Routing**: Forwards to OpenAI if allowed
4. **Evidence**: Creates trace record with decision tree

**11:20 AM — Dashboard View**
Marcus opens the TraceTramp TUI:
```bash
$ tracetramp tui
```

He sees:
- **Active Calls**: 3 in-flight requests
- **Recent Decisions**: Allow, Allow, Block (with reasons)
- **Budget Burn**: $127.45 / $2000.00 this month
- **Decision Trees**: Expandable view of why each decision was made

**2:00 PM — Enforcement in Action**
An engineer accidentally sends a prompt with customer PII:
```
[POLICY BLOCKED] PII detected in prompt
[tracetramp] Policy: no-pii-in-prompts
[tracetramp] Action: block with redaction suggestion
[tracetramp] Dashboard: http://localhost:9742/admin
```

The request never reaches OpenAI. The engineer sees the redacted suggestion and fixes their prompt.

**Outcome**: Marcus has runtime governance without changing application code.

---

### Story 3: Jennifer (Compliance Officer) — WitnessCtl for Audit Evidence

**1:00 PM — The Audit Requirement**
Jennifer's company needs to prove API interactions for SOC 2 compliance. She needs:
- Immutable capture of all AI API calls
- Chain of custody verification
- Auditor-ready export formats
- HITL review for sensitive sessions

**1:15 PM — Starting WitnessCtl**
```bash
$ witnessctl start --name "q1-audit-scope"
[witnessctl] Session: wit-abc123-def456
[witnessctl] Proxy: http://localhost:7443/witness/wit-abc123-def456
[witnessctl] TUI: http://localhost:7444
[witnessctl] Status: capturing
```

**1:20 PM — Configuring the Application**
Jennifer's team routes API traffic through WitnessCtl:
```bash
export OPENAI_BASE_URL="http://localhost:7443/witness/wit-abc123-def456"
export ANTHROPIC_BASE_URL="http://localhost:7443/witness/wit-abc123-def456"
```

**1:30 PM — Live Capture**
The TUI shows:
- **Capture Count**: 247 requests captured
- **Chain Status**: [CHAIN OK] — all receipts verified
- **PII Hits**: 12 detected, 12 redacted
- **Custody Status**: Quorum 2/3 (awaiting 1 more witness)

Each capture shows:
- Request/response headers (sanitized)
- HMAC receipt for tamper verification
- Cost attribution
- Decision digest (why it was allowed/blocked)

**3:00 PM — HITL Review**
A high-risk call triggers human-in-the-loop:
```
[HITL HOLD] Financial tool invocation detected
Tool: transfer_funds
Amount: $50,000.00
Destination: external-account-xyz
```

Jennifer opens the TUI, reviews the request, and clicks:
- **Approve**: Releases the call with logged justification
- **Reject**: Blocks with reason recorded
- **Escalate**: Sends to senior approver

**5:00 PM — Sealing the Session**
```bash
$ witnessctl seal wit-abc123-def456 --name "Q1 AI Interactions"
[witnessctl] Creating evidence bundle...
[witnessctl] ✓ Sealed: ~/Downloads/witnessctl-wit-abc123-def456.witness
[witnessctl] Chain hash: sha256:abc...
[witnessctl] Custody: 3/3 witnesses confirmed
```

**5:15 PM — Compliance Export**
Jennifer exports for the auditor:
```bash
$ witnessctl export wit-abc123-def456 --format pdf --framework soc2
[witnessctl] Generating SOC 2 control mapping...
[witnessctl] ✓ Exported: ~/Downloads/witnessctl-soc2-q1.pdf
```

The PDF includes:
- Executive summary with custody status
- Control-to-evidence mapping (CC6.1, CC6.6, CC7.2)
- Request samples with verification badges
- Chain integrity proof
- Reviewer action log

**Outcome**: Jennifer delivers auditor-ready evidence with cryptographic proof.

---

### Story 4: Alex (DevOps Lead) — Full Connector OS Stack

**Monday — The Deployment**
Alex installs the full Connector OS suite:
```bash
curl -sSL https://cdn.cnktros.com/releases/latest/install.sh | bash
```

**Configuration:**
```yaml
# ~/.config/connector-os/config.yaml
license:
  key: lic-xxx-xxx
  server: https://api.cnktros.com

devguard:
  enabled: true
  policies:
    - no-secrets-in-commits
    - require-linear-history
    - no-force-push-main

tracetramp:
  enabled: true
  port: 9741
  default_provider: openai
  budgets:
    monthly: 5000.00
    per_project:
      api-service: 2000.00
      ml-pipeline: 3000.00

witnessctl:
  enabled: true
  port: 7443
  auto_start_sessions: true
  compliance_frameworks:
    - soc2
    - iso27001
```

**Tuesday — Git Repository Governance**
Alex runs `devguard cage start` in each repository. The team sees:
- Pre-commit hooks preventing secrets
- Dashboard showing commit health across all repos
- Weekly governance reports in Slack

**Wednesday — LLM Traffic Governance**
Alex updates the team's OpenAI client configs to point at TraceTramp. He sees:
- Real-time spend tracking per project
- Policy blocks for PII and high-cost requests
- Decision trees explaining every allow/block

**Thursday — Audit Trail**
Alex configures WitnessCtl to capture all API interactions. The compliance team gets:
- Automatic session sealing every 24 hours
- HMAC-verified evidence chains
- One-click compliance exports

**Friday — The Full Picture**
Alex opens the Connector OS dashboard and sees:
- **DevGuard**: 47 repos protected, 3 policy violations blocked this week
- **TraceTramp**: $1,247.32 spent this month, 12 requests held for review
- **WitnessCtl**: 3 sealed sessions, all chains verified, SOC 2 export ready

**Outcome**: Alex has unified governance across code, LLM usage, and audit evidence.

---

### Story 5: New User Journey — Playground to Production

**Minute 0: Landing on try.cnktros.com**
User sees:
```
┌─────────────────────────────────────────────────────────────┐
│  Connector OS Playground                                    │
│                                                             │
│  Experience AI governance without installing anything.      │
│                                                             │
│  [Start 15-min Session]                                     │
│                                                             │
│  Three tools to try:                                        │
│  • DevGuard — Govern your coding sessions                   │
│  • TraceTramp — Control LLM traffic                         │
│  • WitnessCtl — Capture audit evidence                      │
└─────────────────────────────────────────────────────────────┘
```

**Minute 1: Spawn Session**
User clicks "Start Session" and gets:
- Web-based terminal (xterm.js)
- Pre-configured environment
- All three tools installed and ready

**Minute 2: Try DevGuard**
```bash
$ devguard start
[devguard] Starting governed session...
[devguard] ✓ Dashboard ready: Click to open
```

User sees the dashboard with live monitoring.

**Minute 5: Try TraceTramp**
```bash
$ tracetramp demo-request
[tracetramp] Sending test request...
[tracetramp] Decision: allow
[tracetramp] Cost: $0.0023
[tracetramp] View trace: Click here
```

**Minute 8: Try WitnessCtl**
```bash
$ witnessctl demo-capture
[witnessctl] Capturing sample API interaction...
[witnessctl] ✓ Sealed to evidence bundle
[witnessctl] Chain: [CHAIN OK]
```

**Minute 12: Understanding the Value**
The playground shows a summary:
```
Your 15-minute session demonstrated:
✓ DevGuard prevented 1 secret leak
✓ TraceTramp controlled 3 LLM requests
✓ WitnessCtl captured 3 evidence receipts

Ready to use Connector OS locally?
[Download for macOS] [Download for Linux]
```

**Minute 15: Download and Install**
User clicks download, runs the installer, and transitions to local usage with a Community license.

---

## Part III: Reference Tables

### Scale-Out Path

| Stage       | Trigger            | Action                                          | Cost    |
|-------------|--------------------|-------------------------------------------------|---------|
| Launch      | 0–100 customers    | Current setup                                   | ~$15/mo |
| Growth      | 100–1k customers   | Fly VM: shared-cpu-2x + 1GB RAM               | ~$30/mo |
| Scale       | 1k–10k customers   | Neon scale plan + read replica                | ~$80/mo |
| Production  | 10k+ customers     | Fly performance-2x, Neon Business plan          | ~$200/mo|
| Enterprise  | 50k+ customers     | Multi-region, Fly autoscale min/max 2/10        | custom  |

### File Reference

| File                                      | Purpose                                    |
|-------------------------------------------|--------------------------------------------|
| `platform/deploy/fly.license.toml`        | Fly.io config — license server             |
| `platform/deploy/fly.playground.toml`     | Fly.io config — playground node            |
| `platform/deploy/Dockerfile.license`      | Multi-stage Rust build — license server    |
| `platform/deploy/Dockerfile.playground`   | Multi-stage Rust build — playground node   |
| `platform/deploy/scripts/fly-deploy.sh`   | Deploy helper (init / license / playground)|
| `platform/deploy/scripts/backup-db.sh`    | Hot backup to Cloudflare R2                |
| `platform/licensing/migrations/`          | SQL schema migrations (auto-run on start)  |
| `platform/ui-leptos/admin/vercel.json`    | Vercel config for admin SPA                |

### Local Development

```bash
# Start Postgres locally (Docker)
docker run -d --name pg-local \
  -e POSTGRES_DB=connector \
  -e POSTGRES_PASSWORD=dev \
  -p 5432:5432 postgres:16-alpine

# Run license server
DATABASE_URL="postgres://postgres:dev@localhost/connector" \
CONNECTOR_LICENSE_ADMIN_KEY="devkey123" \
CONNECTOR_LICENSE_ADDR="0.0.0.0:4100" \
cargo run --manifest-path platform/licensing/Cargo.toml

# Test health
curl http://localhost:4100/health
```

---

*End of Deployment Guide*
