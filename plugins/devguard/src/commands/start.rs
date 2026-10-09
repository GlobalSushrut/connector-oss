use anyhow::{Context, Result};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::commands::connect;
use crate::connector_client::ConnectorClient;

pub async fn run(client: &ConnectorClient) -> Result<()> {
    println!("DevGuard Start Wizard\n");

    let workspace = detect_git_workspace()?;
    println!("✓ git workspace: {}", workspace.display());

    let tool = prompt_with_default("Agent tool (cursor/windsurf/claude-code)", "cursor")?;
    let connector_access_key =
        prompt_with_default("Connector access key (blank for dev mode <=3 agents)", "")?;

    let mut unlock_mode = "dev_bypass".to_string();
    if !connector_access_key.trim().is_empty() {
        unlock_mode = "connector_key".to_string();
    } else {
        let agents = prompt_with_default("Dev mode agents allowed [<=3]", "3")?;
        let parsed = agents.trim().parse::<usize>().unwrap_or(3);
        if parsed > 3 {
            anyhow::bail!("Dev mode allows up to 3 agents. Provide Connector access key for larger teams.");
        }
    }

    let team_role_key = prompt_with_default("Team role key (blank => default mid_developer)", "")?;
    let role = if team_role_key.trim().is_empty() {
        "mid_developer".to_string()
    } else {
        let webapp_token = prompt_with_default("Webapp login session token (required for team key)", "")?;
        if webapp_token.trim().is_empty() {
            anyhow::bail!("Webapp login token is required when using team role key.");
        }
        parse_role_from_team_key(&team_role_key).unwrap_or_else(|| "team_member".to_string())
    };

    let config_path = workspace.join("devguard.yaml");
    if !config_path.exists() {
        std::fs::write(&config_path, default_mid_developer_config())
            .with_context(|| format!("Failed to write {}", config_path.display()))?;
        println!("✓ generated default mid_developer config at {}", config_path.display());
    }

    let profile_path = workspace.join(".devguard").join("start_profile.json");
    if let Some(parent) = profile_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let profile = json!({
        "workspace": workspace,
        "tool": tool,
        "unlock_mode": unlock_mode,
        "role": role,
        "connector_url": client.base_url(),
        "team_role_key_present": !team_role_key.trim().is_empty(),
    });
    std::fs::write(&profile_path, serde_json::to_string_pretty(&profile)?)?;
    println!("✓ saved startup profile at {}", profile_path.display());

    let fs_guard_preview = crate::fs_guard::guard_content(
        "File: .env\nFile: src/main.rs",
        &crate::config::ResolvedRole {
            role_name: role.clone(),
            identity: "*".to_string(),
            tool: tool.to_lowercase().replace('-', "_"),
            config: crate::config::DevGuardConfig::load(config_path.to_string_lossy().as_ref())?
                .resolve_role("*", &tool.to_lowercase().replace('-', "_"))
                .map(|r| r.config)
                .unwrap_or_default(),
        },
    );
    println!(
        "✓ fs guard preview: {} (modified={}, {} -> {})",
        fs_guard_preview.verdict,
        fs_guard_preview.content_modified,
        fs_guard_preview.original_length,
        fs_guard_preview.sanitized_length
    );

    if !connector_access_key.trim().is_empty() {
        std::env::set_var("CONNECTOR_ACCESS_KEY", connector_access_key.trim());
    }

    let current = std::env::current_dir()?;
    std::env::set_current_dir(&workspace)?;
    let connect_result = connect::run(
        client,
        Some(&tool),
        Some(&role),
        true,
        config_path.to_string_lossy().as_ref(),
        false,
        false,
    )
    .await;
    std::env::set_current_dir(current)?;
    let session_id = connect_result?;

    let dashboard_state_path = workspace.join(".devguard").join("dashboard.json");
    std::fs::write(
        &dashboard_state_path,
        serde_json::to_string_pretty(&json!({
            "session_id": session_id,
            "workspace": workspace,
            "started_at": chrono::Utc::now().to_rfc3339(),
            "mode": "detached_live",
        }))?,
    )?;

    match spawn_detached_dashboard(&session_id) {
        Ok(()) => {
            println!("✓ launched detached live DevGuard dashboard");
        }
        Err(e) => {
            println!("⚠ detached dashboard launch failed: {}", e);
            println!("  run manually: devguard dashboard --session {}", session_id);
        }
    }
    match spawn_status_api_background(&session_id, config_path.to_string_lossy().as_ref()) {
        Ok(()) => println!("✓ started extension status API on http://127.0.0.1:7788/devguard/status"),
        Err(e) => println!("⚠ could not start extension status API: {}", e),
    }
    match spawn_live_monitor_background(&session_id) {
        Ok(()) => println!("✓ started 24x7 live monitor heartbeat"),
        Err(e) => println!("⚠ could not start live monitor: {}", e),
    }

    println!("\n✓ DevGuard live session started.");
    println!("  Session: {}", session_id);
    println!("  Next: run `devguard status` to watch governed activity.");
    Ok(())
}

fn spawn_detached_dashboard(session_id: &str) -> Result<()> {
    let exe = std::env::current_exe().context("Unable to determine devguard binary path")?;
    let cmd = format!(
        "'{}' dashboard --session '{}' ; printf '\\n[DevGuard dashboard closed] Press Enter to close window...'; read _",
        exe.to_string_lossy(),
        session_id.replace('\'', "'\\''")
    );

    let candidates: [(&str, &[&str]); 4] = [
        ("x-terminal-emulator", &["-e", "sh", "-lc"]),
        ("gnome-terminal", &["--", "sh", "-lc"]),
        ("konsole", &["-e", "sh", "-lc"]),
        ("kitty", &["sh", "-lc"]),
    ];

    for (bin, prefix) in candidates {
        let mut command = Command::new(bin);
        for p in prefix {
            command.arg(p);
        }
        command
            .arg(&cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if command.spawn().is_ok() {
            return Ok(());
        }
    }

    anyhow::bail!(
        "No supported terminal emulator found. Install x-terminal-emulator/gnome-terminal/konsole/kitty."
    )
}

fn spawn_status_api_background(session_id: &str, config_path: &str) -> Result<()> {
    let exe = std::env::current_exe().context("Unable to determine devguard binary path")?;
    let mut cmd = Command::new(exe);
    cmd.args([
        "serve-status",
        "--session",
        session_id,
        "--host",
        "127.0.0.1",
        "--port",
        "7788",
        "--config",
        config_path,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    let child = cmd.spawn().context("Failed to spawn status API process")?;
    let _ = std::fs::write(".devguard/status_api.pid", child.id().to_string());
    Ok(())
}

fn spawn_live_monitor_background(session_id: &str) -> Result<()> {
    let exe = std::env::current_exe().context("Unable to determine devguard binary path")?;
    let mut cmd = Command::new(exe);
    cmd.args([
        "monitor",
        "--session",
        session_id,
        "--interval",
        "2",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    let child = cmd.spawn().context("Failed to spawn live monitor process")?;
    let _ = std::fs::create_dir_all(".devguard");
    let _ = std::fs::write(".devguard/live_monitor.pid", child.id().to_string());
    Ok(())
}

fn detect_git_workspace() -> Result<PathBuf> {
    let out = Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .context("Failed to run git. Is git installed?")?;
    if !out.status.success() {
        anyhow::bail!("Not inside a git project. Run this from your repository root.");
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(Path::new(&root).to_path_buf())
}

fn prompt_with_default(prompt: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        print!("{}: ", prompt);
    } else {
        print!("{} [{}]: ", prompt, default);
    }
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn parse_role_from_team_key(team_key: &str) -> Option<String> {
    let normalized = team_key.trim().replace('-', "_");
    let mut parts = normalized.split('_');
    let _prefix = parts.next()?;
    let maybe_role = parts.next()?;
    if maybe_role.is_empty() {
        None
    } else {
        Some(maybe_role.to_string())
    }
}

fn default_mid_developer_config() -> String {
    r#"version: "2.0"
workspace: default
identity:
  provider: local
  require_auth: false
roles:
  mid_developer:
    clearance: 3
    files:
      read: ["src/**", "tests/**", "docs/**", "*.md", "*.toml", "*.yaml", "*.json"]
      write: ["src/**", "tests/**", "docs/**"]
      hidden: [".env*", "secrets/**", "*.pem", "*.key"]
      read_only: ["infra/**", "database/migrations/**"]
    execution:
      allow: ["cargo*", "npm*", "pytest*", "make", "git status", "git diff", "git add", "git commit", "git log*"]
      deny: ["rm -rf*", "sudo*", "curl | bash", "eval*"]
      require_approval: ["git push*"]
    branches:
      allow: ["feature/*", "fix/*", "refactor/*"]
      deny: ["main", "production"]
    secrets: none
    network:
      allow: ["github.com", "crates.io", "npmjs.com", "pypi.org"]
      deny: ["*"]
    budget:
      max_tokens_per_task: 300000
      max_cost_usd_per_day: 10.00
      model: standard
default_role: mid_developer
assignments:
  - identity: "*"
    role: mid_developer
    tools: ["*"]
"#
    .to_string()
}
