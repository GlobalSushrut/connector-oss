# 68 — DevGuard: Governed Execution for Coding Agents

> DevGuard is Connector's execution governance plugin for coding agents. It controls what Claude Code, Cursor, Windsurf, Kiro, and any coding agent can see, touch, run, and prove — turning ungoverned AI coding into auditable, policy-enforced operations.

---

## The Problem: Ungoverned Coding Agents

Current AI coding assistants have unlimited access:
- Read any file in the workspace
- Execute any shell command
- Write code without verification
- Access secrets and credentials
- No audit trail of what was changed or why

DevGuard solves this by placing a governance control plane between the coding agent and the actual execution environment.

---

## DevGuard Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Coding Agent (Claude/Cursor/etc)           │
│              Thinks it has full access                  │
└─────────────────────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   DevGuard Gateway      │
              │   (Anthropic/OpenAI     │
              │    compatible API)       │
              └───────────┬───────────────┘
                          │
    ┌─────────────────────┼─────────────────────┐
    │                     │                     │
    ▼                     ▼                     ▼
┌─────────┐        ┌─────────┐          ┌─────────┐
│FS Guard │        │Exec Guard│         │Secret  │
│(files)  │        │(commands)│        │Broker  │
└─────────┘        └─────────┘          └─────────┘
    │                     │                     │
    └─────────────────────┼─────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   9 Rings Enforcement │
              │   Audit Chain Record   │
              └─────────────────────────┘
```

---

## Core Components

### 1. FS Guard — File System Governance

Controls what files the agent can read/write:

```rust
pub struct FileVisibilityRule {
    pub path_pattern: String,
    pub visibility: VisibilityLevel,
    pub mask_patterns: Vec<String>,  // Regex for redaction
}

pub enum VisibilityLevel {
    Read,       // Agent can read
    Hidden,     // Agent cannot see file exists
    Masked,     // Agent sees redacted version
    Write,      // Agent can modify
}
```

**Policy Example:**

```yaml
# .connector/policy.yaml
files:
  # Secrets - completely hidden
  - pattern: "**/.env*"
    visibility: hidden
    
  - pattern: "**/secrets/**"
    visibility: hidden
    
  # Config files - masked (show structure, hide values)
  - pattern: "**/config.yaml"
    visibility: masked
    mask_patterns:
      - "api_key: .*"
      - "password: .*"
      - "token: .*"
      
  # Generated files - deny writes
  - pattern: "**/node_modules/**"
    visibility: read
    allow_write: false
    
  # Source code - full access
  - pattern: "src/**"
    visibility: read
    allow_write: true
```

### 2. Exec Guard — Command Execution Governance

Controls what shell commands can run:

```rust
pub struct ExecGuardResult {
    pub allowed: bool,
    pub verdict: String,        // ALLOW, DENY, APPROVE_REQUIRED
    pub reason: String,
    pub command: String,
    pub dangerous: bool,
    pub network_egress: bool,
    pub requires_approval: bool,
    pub approval_from: Vec<String>,
}
```

**Always Deny (Hardcoded):**
- `rm -rf /` — Recursive root delete
- `:(){ :|:& };:` — Fork bomb
- `> /dev/sda` — Block device write
- `mkfs.*` — Filesystem format
- `chmod -R 777 /` — Permission removal

**Always Flag (Policy Governed):**
- `curl | bash` — Remote code execution
- `eval *` — Dynamic code execution
- `sudo *` — Privilege escalation
- `ssh *` — Remote shell access

**Policy Example:**

```yaml
execution:
  # Allow safe development commands
  allow:
    - "npm install"
    - "npm run build"
    - "cargo build"
    - "cargo test"
    - "pytest"
    - "python -m pytest"
    
  # Require approval for dangerous commands
  require_approval:
    - pattern: "pip install.*"
      approvers: ["security-team"]
      reason: "External package installation"
      
    - pattern: "docker.*"
      approvers: ["devops-team"]
      reason: "Container operations"
      
    - pattern: "git push.*--force"
      approvers: ["lead-dev"]
      reason: "Force push can lose history"
      
  # Always deny
  deny:
    - "rm -rf *"
    - "*:(){ :|:& };:*"  # Fork bomb pattern
    - "> /dev/*"
```

### 3. Secret Broker — Credential Governance

Manages secret access without exposing values:

```rust
pub struct SecretBroker {
    pub patterns: Vec<SecretPattern>,
    pub vault: VaultBackend,
}

pub enum SecretPattern {
    ApiKey(String),      // Detects "api_key: ..."
    Password(String),    // Detects "password: ..."
    Token(String),       // Detects "token: ..."
    PrivateKey(String),  // Detects PEM keys
    ConnectionString(String), // Database URLs
}
```

**Behavior:**
- Detects secrets in agent context
- Redacts before sending to LLM
- Provides vault reference instead of value
- Logs access in audit chain

---

## DevGuard Session

A governed session wraps a coding agent with full policy enforcement:

```rust
pub struct DevGuardSession {
    pub session_id: String,
    pub agent_pid: String,
    pub role: String,              // builder, reviewer, admin
    pub workspace: String,
    pub tool: String,              // claude_code, cursor, windsurf
    pub policy_path: String,
    pub active: bool,
    pub stats: SessionStats,
}

pub struct SessionStats {
    pub llm_calls: u64,
    pub files_read: u64,
    pub files_written: u64,
    pub commands_executed: u64,
    pub commands_denied: u64,
    pub secrets_redacted: u64,
    pub approvals_requested: u64,
    pub tokens_consumed: u64,
    pub cost_usd: f64,
}
```

---

## CLI Commands

```bash
# Start governed session for Claude Code
$ connectorctl guard claude --role builder --workspace ./my-project
Session: dg_a3f7b2c8d9e1
Agent: devguard-claude-a3f7b2
Policy: .connector/policy.yaml (loaded)

# Start governed session for Cursor
$ connectorctl guard cursor --role reviewer --workspace ./another-project

# Start proxy for any tool
$ connectorctl guard proxy --port 8080 --policy ./strict-policy.yaml

# Watch active sessions
$ connectorctl guard watch
SESSION        TOOL     ROLE      STATUS   FILES   CMDS
─────────────────────────────────────────────────────────────
dg_a3f7b2c8    claude   builder   active   42      12
dg_b4c9d3e1    cursor   reviewer  active   8       3

# Generate audit report
$ connectorctl guard audit --session dg_a3f7b2c8
Files read: 42
Files written: 7
Commands executed: 12
Commands denied: 2
  - "rm -rf node_modules" (policy: deny recursive delete)
  - "curl https://example.com/script.sh | bash" (policy: deny remote exec)
Secrets redacted: 5
Approvals requested: 1
  - pip install pandas (approved by security-team)

# Generate proof bundle
$ connectorctl guard proof --session dg_a3f7b2c8
Proof CID: soe1-sha256-d4e8f1a3...
All 9 chains verified: ✓
```

---

## API Endpoints

```bash
# Start session
POST /api/v1/devguard/session/start
{
  "role": "builder",
  "workspace": "/projects/my-app",
  "tool": "claude_code",
  "policy_yaml": "..."
}

# Execute command (through session)
POST /api/v1/devguard/exec
{
  "session_id": "dg_a3f7b2c8",
  "command": "npm install",
  "working_dir": "/projects/my-app"
}
Response:
{
  "allowed": true,
  "verdict": "ALLOW",
  "executed": true,
  "exit_code": 0,
  "stdout": "...",
  "audit_cid": "mem1-sha256-..."
}

# Read file (through session)
POST /api/v1/devguard/fs/read
{
  "session_id": "dg_a3f7b2c8",
  "path": "src/main.rs"
}
Response:
{
  "content": "fn main() {...}",
  "visibility": "read",
  "secrets_redacted": 0,
  "audit_cid": "mem1-sha256-..."
}
```

---

## Supported Tools

| Tool | Integration | Protocol |
|------|-------------|----------|
| Claude Code | `ANTHROPIC_BASE_URL` | Anthropic Messages |
| Cursor | `openai_base_url_override` | OpenAI Chat |
| Windsurf | MCP Server | MCP + OpenAI |
| Kiro | `anthropic_base_url` | Anthropic Messages |
| Generic | Env var | OpenAI or Anthropic |

Those base URLs are **voluntary** unless the host vendor cut applied. A DevGuard session (like Talk or MCP register) can engage `GET /api/v1/runtime/llm-vendor-cut`. The cage itself is generic — [WORLD_CAGE_AND_BROWSER.md](WORLD_CAGE_AND_BROWSER.md).

---

## Policy YAML Structure

```yaml
# .connector/policy.yaml
version: "1.0"
description: "Development governance policy"

roles:
  builder:
    description: "Standard developer"
    permissions:
      files: [read, write]
      execution: [allowed, approval_required]
      secrets: [redacted]
      
  reviewer:
    description: "Code reviewer - read only"
    permissions:
      files: [read]
      execution: [deny]
      
  admin:
    description: "Full access with audit"
    permissions:
      files: [read, write]
      execution: [allowed]
      approvals_can_grant: ["*"]

files:
  - pattern: "**/.env*"
    visibility: hidden
    
  - pattern: "src/**"
    visibility: read
    allow_write: true
    
execution:
  allow:
    - "npm *"
    - "cargo *"
    - "pytest"
    
  require_approval:
    - pattern: "pip install.*"
      approvers: ["security-team"]
      
    - pattern: "docker .*"
      approvers: ["devops-team"]
      
  deny:
    - "rm -rf *"
    - "curl *|*sh"
    
shell:
  timeout_seconds: 300
  max_output_mb: 10
  network_egress: allowed  # denied | allowed | monitored
  
verification:
  post_write_checks:
    - "cargo check"
    - "cargo test --lib"
    - "cargo clippy"
  on_failure: rollback  # rollback | warn | ignore
  
cost:
  daily_budget_usd: 50.0
  model_routing:
    default: "claude-3-5-sonnet"
    large_contexts: "claude-3-opus"
    simple_tasks: "claude-3-haiku"
    
notifications:
  webhooks:
    - url: "${SLACK_WEBHOOK}"
      events: ["approval_required", "policy_violation"]
```

---

## Real-World Use Case: Safe CI/CD

```bash
# DevGuard in CI/CD pipeline
$ export ANTHROPIC_BASE_URL=https://connector.internal:8443/v1
$ export ANTHROPIC_API_KEY=connector-session-dg_ci_a3f7b2

# Claude Code runs in governed session
$ claude "Update dependencies and run tests"

# DevGuard enforces:
# ✓ Files accessed are in allowlist
# ✓ Commands executed are safe
# ✓ Secrets are redacted from context
# ✓ Tests pass before changes committed
# ✓ Full audit trail generated
# ✗ Dangerous commands blocked
# ✗ Unauthorized files hidden
```

---

## Migration Path

**Before:** Direct tool access
```bash
$ claude  # Has full system access
```

**After:** Governed session
```bash
$ connectorctl guard claude  # Controlled by policy
```

No code changes required in the agent — the governance is transparent at the API level.
