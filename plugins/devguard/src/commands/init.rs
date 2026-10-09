//! `devguard init` — create devguard.yaml in the current workspace.

use anyhow::Result;
use crate::config::DevGuardConfig;

pub async fn run(team: bool, provider: &str, org: Option<&str>) -> Result<()> {
    let path = "devguard.yaml";

    if std::path::Path::new(path).exists() {
        eprintln!("devguard.yaml already exists. Use --force to overwrite.");
        std::process::exit(1);
    }

    let content = if team {
        generate_team_template(provider, org)
    } else {
        generate_single_user_template()
    };

    std::fs::write(path, &content)?;

    if team {
        let mut cfg = DevGuardConfig::load(path)?;
        crate::commands::team::collect_team_assignments_interactive(provider, &mut cfg)?;
        std::fs::write(path, serde_yaml::to_string(&cfg)?)?;
    }

    println!("✓ Created devguard.yaml");
    if team {
        println!("✓ Team mode: {} provider{}", provider,
            if let Some(o) = org { format!(", org: {}", o) } else { String::new() });
        println!("  Edit devguard.yaml to assign roles to your team.");
    } else {
        println!("  Single user, builder role. Edit devguard.yaml to customize.");
    }

    Ok(())
}

fn generate_single_user_template() -> String {
    r#"# DevGuard Configuration — Single User
# Docs: https://docs.connector.dev/devguard
$schema: "./plugins/devguard/devguard.schema.json"
version: "2.0"
workspace: my-project

identity:
  provider: local
  require_auth: false

roles:
  builder:
    clearance: 3
    files:
      read: ["src/**", "tests/**", "docs/**", "*.toml", "*.json", "*.yaml", "*.md"]
      write: ["src/**", "tests/**"]
      hidden: [".env*", "*.key", "*.pem", "secrets/**"]
      read_only: ["infra/**", "database/migrations/**"]
    execution:
      allow:
        - "cargo build"
        - "cargo test"
        - "cargo check"
        - "cargo clippy"
        - "cargo fmt"
        - "npm test"
        - "npm run build"
        - "npm run lint"
        - "pytest"
        - "make"
        - "git status"
        - "git diff"
        - "git add"
        - "git commit"
        - "git log*"
        - "git branch"
        - "git checkout*"
      deny:
        - "rm -rf*"
        - "sudo*"
        - "curl | bash"
        - "eval*"
        - "ssh*"
      require_approval:
        - "git push*"
    branches:
      allow: ["feature/*", "fix/*", "refactor/*"]
      deny: ["main", "production"]
    secrets: none
    network:
      allow: ["pypi.org", "npmjs.com", "crates.io", "github.com"]
      deny: ["*"]
    budget:
      max_tokens_per_task: 500000
      max_cost_usd_per_day: 10.00
      model: standard

default_role: builder

files:
  always_hidden: [".env*", "*.key", "*.pem", "*.p12", "secrets/**", ".git/config"]
  always_read_only: ["LICENSE"]

secrets:
  detect_and_redact: true
  patterns: default

git:
  no_force_push: true
  max_diff_lines: 2000
  protected_branches: ["main", "production"]

budget:
  max_tokens_per_day: 1000000
  max_cost_usd_per_day: 20.00
  alert_at_percent: 80

audit:
  level: full
  receipts: true
  proof: true
  retention_days: 30

enforcement:
  mode: hooks
  deny_by_default: true
  least_privilege: true
  no_raw_secret_exposure: true
  all_actions_receipted: true
"#.to_string()
}

fn generate_team_template(provider: &str, org: Option<&str>) -> String {
    let org_str = org.unwrap_or("my-company");
    format!(r#"# DevGuard Configuration — Team RBAC
# Docs: https://docs.connector.dev/devguard
$schema: "./plugins/devguard/devguard.schema.json"
version: "2.0"
workspace: {org}/my-project

# ── Identity Provider ────────────────────────────────────────
identity:
  provider: {provider}
  org: {org}
  require_auth: true
  mfa_required: false

# ── Roles ────────────────────────────────────────────────────
roles:

  intern:
    clearance: 1
    files:
      read: ["src/**", "tests/**", "docs/**", "README.md"]
      write: ["tests/**"]
      hidden: ["infra/**", "deploy/**", ".env*", "secrets/**",
               "src/auth/**", "src/billing/**", "database/migrations/**"]
    execution:
      allow: ["cargo test", "cargo check", "npm test", "npm run lint",
              "git status", "git diff", "git log -n *"]
      deny: ["*"]
      require_approval: ["git push*"]
    branches:
      allow: ["feature/intern-*"]
    secrets: none
    network:
      allow: ["pypi.org", "npmjs.com", "crates.io"]
      deny: ["*"]
    budget:
      max_tokens_per_task: 50000
      max_cost_usd_per_day: 2.00
      model: cheap
    approvals:
      all_writes: {{ require: senior }}

  junior:
    clearance: 2
    extends: intern
    files:
      read: ["src/**", "tests/**", "docs/**", "*.toml", "*.json", "*.yaml", "*.md"]
      write: ["src/**", "tests/**"]
      hidden: [".env*", "secrets/**", "infra/prod/**", "database/migrations/**"]
      read_only: ["infra/dev/**", "src/auth/**"]
    execution:
      allow: ["cargo build", "cargo test", "cargo check", "cargo clippy",
              "npm test", "npm run build", "npm run lint", "pytest",
              "git status", "git diff", "git add", "git commit", "git log*"]
      deny: ["rm -rf*", "sudo*", "curl | bash", "eval*", "ssh*",
             "docker*", "kubectl*", "terraform*"]
      require_approval: ["git push*"]
    branches:
      allow: ["feature/*", "fix/*"]
      deny: ["main", "release/*", "production"]
    secrets: none
    network:
      allow: ["pypi.org", "npmjs.com", "crates.io", "github.com"]
      deny: ["*"]
    budget:
      max_tokens_per_task: 200000
      max_cost_usd_per_day: 5.00
      model: standard

  senior:
    clearance: 4
    files:
      read: ["**"]
      write: ["src/**", "tests/**", "docs/**", "database/migrations/**"]
      hidden: [".env.production", "secrets/prod/**"]
      read_only: ["infra/prod/**"]
    execution:
      allow: ["cargo*", "npm*", "pytest*", "make", "docker build*",
              "docker compose*", "git*"]
      deny: ["rm -rf /", "sudo rm*", "curl | bash", "eval*"]
      require_approval: ["git push origin main", "docker push*"]
    branches:
      allow: ["feature/*", "fix/*", "refactor/*", "release/*"]
      deny: ["production"]
    secrets:
      allowed_via_broker: ["dev_db_password", "staging_api_key"]
      direct_access: none
    network:
      allow: ["pypi.org", "npmjs.com", "crates.io", "github.com",
              "docker.io", "*.amazonaws.com"]
      deny: ["*"]
    budget:
      max_tokens_per_task: 500000
      max_cost_usd_per_day: 20.00
      model: best

  tech_lead:
    clearance: 5
    extends: senior
    files:
      read: ["**"]
      write: ["**"]
      no_delete: ["migrations/**", "LICENSE"]
    execution:
      allow: ["*"]
      deny: ["rm -rf /", ":()({{ :|:& }};:"]
      require_approval: ["kubectl apply*", "terraform apply*"]
    branches:
      allow: ["*"]
    secrets:
      allowed_via_broker: ["*"]
      direct_access: none
    budget:
      max_tokens_per_task: 1000000
      max_cost_usd_per_day: 50.00

  reviewer:
    clearance: 2
    files:
      read: ["**"]
      write: []
    execution:
      allow: ["cargo check", "cargo clippy", "npm run lint", "pytest",
              "git diff", "git log*", "git blame*", "git status"]
      deny: ["*"]
    secrets: none
    budget:
      max_tokens_per_task: 50000
      model: cheap

# ── Assignments ──────────────────────────────────────────────
# Map identity + tool → role. Edit with your team members.
assignments:
  # Example:
  # - identity: {provider}:alice
  #   role: tech_lead
  #   tools: [claude_code, cursor, windsurf]
  #
  # - identity: {provider}:bob
  #   role: senior
  #   tools: [claude_code]
  #
  # - identity: {provider}:team/frontend
  #   role: junior
  #   tools: [cursor, windsurf]
  #   overrides:
  #     files:
  #       write: ["src/frontend/**", "tests/frontend/**"]

  - identity: "*"
    role: intern
    tools: ["*"]

# ── Global ───────────────────────────────────────────────────
files:
  always_hidden: [".env*", "*.key", "*.pem", "*.p12", "secrets/**",
                  ".git/config", "node_modules/**"]
  always_read_only: ["LICENSE", ".github/CODEOWNERS"]

secrets:
  detect_and_redact: true
  patterns: default
  vault_backend: connector

git:
  no_force_push: true
  max_diff_lines: 2000
  protected_branches: ["main", "production", "release/*"]

budget:
  max_tokens_per_day: 5000000
  max_cost_usd_per_day: 100.00
  alert_at_percent: 80

audit:
  level: full
  receipts: true
  proof: true
  retention_days: 90

enforcement:
  mode: hooks
  deny_by_default: true
  least_privilege: true
  no_raw_secret_exposure: true
  all_actions_receipted: true
"#, org = org_str, provider = provider)
}
