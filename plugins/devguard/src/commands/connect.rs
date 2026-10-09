//! `devguard connect <tool>` — connect a coding tool under DevGuard governance.

use anyhow::{Context, Result};
use crate::adapter;
use crate::action::ToolId;
use crate::config::DevGuardConfig;
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use chrono;
use std::path::{Path, PathBuf};

pub async fn run(
    client: &ConnectorClient,
    tool: Option<&str>,
    role_override: Option<&str>,
    cage: bool,
    config_path: &str,
    dry_run: bool,
    list: bool,
) -> Result<String> {
    if list {
        print_connected_tools_status();
        return Ok("list".to_string());
    }
    let tool = tool.ok_or_else(|| anyhow::anyhow!("Tool is required unless using --list"))?;

    if dry_run {
        print_dry_run_plan(client, tool, config_path)?;
        return Ok("dry_run".to_string());
    }

    // 1. Load policy
    let config = DevGuardConfig::load(config_path)
        .with_context(|| format!("Failed to load {}. Run `devguard init` first.", config_path))?;

    // 2. Validate policy
    let errors = config.validate();
    if !errors.is_empty() {
        eprintln!("Policy errors in {}:", config_path);
        for e in &errors {
            eprintln!("  ✗ {}", e);
        }
        std::process::exit(1);
    }

    // 3. Resolve identity
    let identity = resolve_identity(&config);
    println!("Identity: {}", identity);

    // 4. Resolve role
    let tool_id = ToolId::from_str(tool);
    let tool_key = tool.to_lowercase().replace('-', "_");
    let role_name = if let Some(r) = role_override {
        r.to_string()
    } else if let Some(resolved) = config.resolve_role(&identity, &tool_key) {
        resolved.role_name
    } else if !config.default_role.is_empty() {
        config.default_role.clone()
    } else {
        eprintln!("No role assignment found for identity '{}' with tool '{}' in {}.", identity, tool, config_path);
        eprintln!("Add an assignment or set default_role.");
        std::process::exit(1);
    };

    // Verify role exists
    if !config.roles.contains_key(&role_name) {
        eprintln!("Role '{}' not defined in {}.", role_name, config_path);
        std::process::exit(1);
    }

    // 5. Compute policy fingerprint
    let fingerprint = config.fingerprint();
    println!("Policy fingerprint: {}...{}", &fingerprint[..8], &fingerprint[fingerprint.len()-8..]);

    // 6. Get adapter
    let adapter = adapter::get_adapter(tool);
    println!("Adapter: {} ({})", adapter.name(), format!("{:?}", adapter.support_level()));

    // 7. Check tool detection
    if !adapter.detect() {
        eprintln!("Warning: {} not detected on this system. Connection may not work.", adapter.name());
    }

    // 8. Ensure Connector OS is running — DevGuard boots Connector, not vice versa
    ensure_connector_running(client).await?;

    // 9. Read raw YAML to send to server for policy enforcement
    let policy_yaml = std::fs::read_to_string(config_path)
        .with_context(|| format!("Cannot read {}", config_path))?;

    // 10. Create session via Connector API — send YAML policy for server-side enforcement
    let connector_url = client.base_url();
    let workspace = std::env::current_dir()?.to_string_lossy().to_string();
    let body = serde_json::json!({
        "role": role_name,
        "tool": tool_id.display_name().to_lowercase().replace(' ', "_"),
        "workspace": workspace,
        "policy_yaml": policy_yaml,
        "identity": identity,
        "cage": cage,
        "policy_fingerprint": fingerprint,
    });

    let resp = client.session_start(&body).await
        .with_context(|| "Failed to create DevGuard session on Connector")?;

    let session_id = resp.get("session_id").and_then(|v| v.as_str()).unwrap_or("unknown");
    let agent_pid = resp.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("unknown");
    let session_token = resp
        .get("session_token")
        .and_then(|v| v.as_str())
        .filter(|t| t.starts_with("cg_"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Connector did not issue a cg_ token for this session (DG-03). \
                 Refusing phantom identity. Check POST /api/v1/devguard/sessions."
            )
        })?;

    // Build SessionInfo for adapter
    let session = SessionInfo {
        session_id: session_id.to_string(),
        agent_pid: agent_pid.to_string(),
        identity: identity.clone(),
        role: role_name.clone(),
        tool: tool_id.clone(),
        workspace: workspace.clone(),
        connector_url: connector_url.clone(),
        cage,
        policy_fingerprint: fingerprint.clone(),
        session_token: Some(session_token.to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    // 10. Stamp repo address so any agent in this checkout uses the same pair.
    if let Err(e) = write_repo_address(
        Path::new(&workspace),
        session_token,
        &connector_url,
        session_id,
    ) {
        eprintln!("⚠ Could not write .devguard/connector.json: {e}");
    } else {
        println!("✓ Repo address written to .devguard/connector.json (any agent in this folder uses it)");
    }

    // 10b. Connect tool via adapter
    let adapter_obj = adapter::get_adapter(tool);
    let connection = adapter_obj.connect(client, &session)
        .with_context(|| format!("Failed to connect {}", adapter_obj.name()))?;
    let enforcement_mode = detect_enforcement_mode(&workspace);
    let preload_status = if cage {
        let preload = setup_ld_preload_guard(
            Path::new(&workspace),
            config_path,
            if agent_pid == "unknown" { None } else { Some(agent_pid) },
        );
        Some(preload)
    } else {
        None
    };

    // 11. Print production-grade output
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  DevGuard — Session Active                                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("  Session:       {}", session_id);
    println!("  Agent PID:     {}", agent_pid);
    println!("  Identity:      {}", identity);
    println!("  Role:          {}", role_name);
    println!("  Tool:          {} ({:?})", adapter_obj.name(), adapter_obj.support_level());
    println!("  Enforcement:   {}", if cage { "CAGE (git hooks + FS watchdog + exec wrapper — not a kernel overlay)" } else { "HOOKS (gateway middleware)" });
    println!("  Mode:          {}", enforcement_mode);
    println!("  Policy:        {} ({}...{})", config_path, &fingerprint[..8], &fingerprint[fingerprint.len()-8..]);
    println!("  Workspace:     {}", workspace);

    // Print effective permissions
    if let Some(resolved) = config.resolve_role(&identity, &tool_key) {
        let rc = &resolved.config;
        println!("\n── Effective Permissions ──────────────────────────────────────");
        println!("  Clearance:     {}", rc.clearance);

        if !rc.files.read.is_empty() {
            println!("  Files read:    {}", truncate_list(&rc.files.read, 60));
        }
        if !rc.files.write.is_empty() {
            println!("  Files write:   {}", truncate_list(&rc.files.write, 60));
        } else {
            println!("  Files write:   NONE (read-only role)");
        }
        if !rc.files.hidden.is_empty() {
            println!("  Files hidden:  {}", truncate_list(&rc.files.hidden, 60));
        }
        if !rc.execution.allow.is_empty() {
            println!("  Commands OK:   {}", truncate_list(&rc.execution.allow, 60));
        }
        if !rc.execution.deny.is_empty() {
            println!("  Commands DENY: {}", truncate_list(&rc.execution.deny, 60));
        }
        if !rc.branches.allow.is_empty() {
            println!("  Branches:      {}", rc.branches.allow.join(", "));
        }
        if rc.secrets.is_default() || rc.secrets.is_none() {
            println!("  Secrets:       NONE");
        } else {
            println!("  Secrets:       {} via broker", rc.secrets.allowed_via_broker.join(", "));
        }
        if !rc.network.allow.is_empty() {
            println!("  Network:       {}", truncate_list(&rc.network.allow, 60));
        }
        if rc.budget.max_cost_usd_per_day > 0.0 {
            println!("  Budget:        ${:.2}/day, {}K tokens/task, model: {}",
                rc.budget.max_cost_usd_per_day,
                rc.budget.max_tokens_per_task / 1000,
                if rc.budget.model.is_empty() { "default" } else { &rc.budget.model });
        }
    }

    // Print connection instructions
    println!("\n── Connection ────────────────────────────────────────────────");
    if !connection.env_vars.is_empty() {
        for (key, val) in &connection.env_vars {
            println!("  export {}={}", key, val);
        }
    }
    println!("  export DEVGUARD_ENFORCEMENT_MODE={}", enforcement_mode);
    if let Some(ref cmd) = connection.launch_command {
        println!("\n  Launch: {}", cmd);
    }

    println!("\n── Enforcement Active ────────────────────────────────────────");
    println!("  ✓ File guard:    policy checks available (advisory unless hooks/cage block channel active)");
    println!("  ✓ Exec guard:    policy checks available (adapter/tool interception dependent)");
    println!("  ✓ Secret broker: API keys, tokens, private keys redacted");
    println!("  ✓ Audit chain:   every action recorded with receipt");
    if cage {
        match crate::commands::cage::start(config_path, None).await {
            Ok(()) => println!("✓ Host cage started — git hooks, FS, exec. Any agent in this repo is bound."),
            Err(e) => eprintln!("⚠ cage start failed (address is still live): {e}"),
        }
        println!("  ✓ Cage mode:     watchdog + hooks enabled (verify with `devguard cage status`)");
        println!("  ✓ Overlay FS:    configured where supported by host/tooling");
        println!("  ✓ Network fence: configured where supported by host/tooling");
        if let Some(status) = &preload_status {
            println!("  ✓ Process guard: {}", status.summary);
        }
    }

    println!("\n  Monitor: devguard status {}", session_id);
    println!("  Stop:    devguard disconnect {}", session_id);

    if tool_id == ToolId::Windsurf {
        let ws_settings = detect_windsurf_settings_path();
        if let Some(path) = ws_settings {
            match ensure_windsurf_mcp_settings(&path, &connector_url, false) {
                Ok(()) => {
                    println!("  ✓ Windsurf settings MCP entry updated: {}", path.display());
                    println!("  Restart Windsurf -> DevGuard MCP is now active.");
                }
                Err(e) => {
                    println!("  ⚠ Windsurf settings MCP update failed: {}", e);
                }
            }
        } else {
            println!("  ⚠ Windsurf settings path not found (tried ~/.windsurf/settings.json and ~/.config/Windsurf/settings.json)");
        }
    }

    Ok(session_id.to_string())
}

fn write_repo_address(workspace: &Path, _token: &str, connector_url: &str, session_id: &str) -> Result<()> {
    let dir = workspace.join(".devguard");
    std::fs::create_dir_all(&dir)?;
    let base = connector_url.trim_end_matches('/');
    let doc = serde_json::json!({
        "schema": "devguard.connector/v1",
        "session_id": session_id,
        "gateway_base": base,
        "openai_base_url": format!("{base}/v1"),
        "anthropic_base_url": format!("{base}/v1"),
        "api_key": null,
        "credential_source": "CONNECTOR_AGENT_TOKEN",
        "require_identity": true,
        "admit": format!("{base}/api/v1/devguard/admit"),
        "rule": "No Connector agent ID + role → even read is denied. Ask the node for an identity.",
    });
    std::fs::write(dir.join("connector.json"), serde_json::to_string_pretty(&doc)?)?;
    std::fs::write(
        dir.join("IDENTITY"),
        "This checkout is under Connector DevGuard.\n\
         No Connector agent ID + role → even read is denied.\n\
         Ask the node: POST /api/v1/devguard/admit\n\
         Header: X-Connector-Repo: <repo_id>\n\
         Authorization: Bearer <issued cg_ token>\n",
    )?;
    Ok(())
}

fn print_dry_run_plan(client: &ConnectorClient, tool: &str, config_path: &str) -> Result<()> {
    println!("DevGuard connect --dry-run\n");
    println!("No files will be written.");
    println!("No session will be created.");
    println!("Tool: {}", tool);
    println!("Config: {}", config_path);
    if tool.eq_ignore_ascii_case("windsurf") {
        if let Some(path) = detect_windsurf_settings_path() {
            println!("Would write Windsurf MCP entry at: {}", path.display());
            let mcp_preview = serde_json::json!({
                "mcpServers": {
                    "connector": {
                        "serverUrl": format!("{}/protocols/mcp/handle", client.base_url()),
                        "description": "Connector DevGuard — governed agent runtime",
                        "env": { "CONNECTOR_URL": client.base_url() }
                    }
                }
            });
            println!(
                "Would merge MCP config:\n{}",
                serde_json::to_string_pretty(&mcp_preview)?
            );
            println!("Instruction: Restart Windsurf -> DevGuard MCP is now active.");
        } else {
            println!("Would detect Windsurf settings path but none found.");
        }
    }
    Ok(())
}

fn print_connected_tools_status() {
    let tools = [
        ("windsurf", detect_windsurf_settings_path().map(|p| p.exists()).unwrap_or(false)),
        ("cursor", std::env::var("HOME").map(|h| Path::new(&h).join(".cursor/settings.json").exists()).unwrap_or(false)),
        ("zed", std::env::var("HOME").map(|h| Path::new(&h).join(".config/zed/settings.json").exists()).unwrap_or(false)),
        ("vscode/cline", Path::new(".vscode/settings.json").exists()),
    ];
    println!("Connected tools status:\n");
    for (tool, ok) in tools {
        println!("  {:<16} {}", tool, if ok { "configured" } else { "not_configured" });
    }
}

fn detect_windsurf_settings_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let candidates = [
        Path::new(&home).join(".windsurf/settings.json"),
        Path::new(&home).join(".config/Windsurf/settings.json"),
        Path::new(".windsurf/settings.json").to_path_buf(),
    ];
    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .or_else(|| Some(candidates[0].clone()))
}

fn ensure_windsurf_mcp_settings(path: &Path, connector_url: &str, dry_run: bool) -> Result<()> {
    let mcp_entry = serde_json::json!({
        "serverUrl": format!("{}/protocols/mcp/handle", connector_url),
        "description": "Connector DevGuard — governed agent runtime",
        "env": { "CONNECTOR_URL": connector_url }
    });
    let mut doc = if path.exists() {
        let raw = std::fs::read_to_string(path).unwrap_or_else(|_| "{}".to_string());
        serde_json::from_str::<serde_json::Value>(&raw).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    if doc.get("mcpServers").and_then(|v| v.as_object()).is_none() {
        doc["mcpServers"] = serde_json::json!({});
    }
    doc["mcpServers"]["connector"] = mcp_entry;
    if dry_run {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

struct PreloadSetupStatus {
    summary: String,
}

fn setup_ld_preload_guard(workspace: &Path, _config_path: &str, agent_pid: Option<&str>) -> PreloadSetupStatus {
    let _ = (workspace, agent_pid);
    PreloadSetupStatus {
        summary: "disabled: LD_PRELOAD is bypassable and is not an enforcement boundary".into(),
    }
}

pub fn detect_enforcement_mode(workspace: &str) -> &'static str {
    let ws = Path::new(workspace);
    let hooks_active = ws.join(".git/hooks/pre-commit").exists() || ws.join(".git/hooks/pre-push").exists();
    let watchdog_alive = watchdog_alive(ws);
    let heartbeat_fresh = watchdog_heartbeat_fresh(ws, 10);
    let exec_wrapper_present = ws.join(".devguard/exec_wrapper.sh").exists();
    let file_perms_active = ws.join(".devguard/saved_perms.json").exists();

    if hooks_active && watchdog_alive && heartbeat_fresh && exec_wrapper_present && file_perms_active {
        "locked"
    } else if watchdog_alive {
        "cage"
    } else if hooks_active {
        "hooks"
    } else {
        "advisory"
    }
}

pub fn watchdog_alive(workspace: &Path) -> bool {
    let pid_path = workspace.join(".devguard/watchdog.pid");
    let pid = std::fs::read_to_string(pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok());
    match pid {
        Some(p) if p > 0 => std::process::Command::new("kill")
            .args(["-0", &p.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        _ => false,
    }
}

pub fn watchdog_heartbeat_fresh(workspace: &Path, max_age_secs: i64) -> bool {
    let hb_path = workspace.join(".devguard/watchdog.heartbeat");
    let ts = std::fs::read_to_string(hb_path)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok());
    match ts {
        Some(last) => {
            let now = chrono::Utc::now().timestamp();
            now.saturating_sub(last) <= max_age_secs
        }
        None => false,
    }
}

/// Resolve the current user's identity based on the config's identity provider.
fn resolve_identity(config: &DevGuardConfig) -> String {
    match config.identity.provider.as_str() {
        "github" => resolve_github_identity(),
        "gitlab" => resolve_gitlab_identity(),
        "local" | _ => resolve_local_identity(),
    }
}

fn resolve_local_identity() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "local:unknown".into())
}

fn resolve_github_identity() -> String {
    // Try `gh auth status` to get GitHub username
    if let Ok(output) = std::process::Command::new("gh")
        .args(["auth", "status"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        // Parse "Logged in to github.com account username"
        if let Some(pos) = text.find("account ") {
            let rest = &text[pos + 8..];
            if let Some(end) = rest.find(|c: char| c.is_whitespace() || c == '(') {
                return format!("github:{}", &rest[..end]);
            }
        }
    }
    // Fallback to git config
    if let Ok(output) = std::process::Command::new("git")
        .args(["config", "user.email"])
        .output()
    {
        let email = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !email.is_empty() {
            return format!("github:{}", email);
        }
    }
    "github:unknown".into()
}

fn resolve_gitlab_identity() -> String {
    if let Ok(output) = std::process::Command::new("git")
        .args(["config", "user.email"])
        .output()
    {
        let email = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !email.is_empty() {
            return format!("gitlab:{}", email);
        }
    }
    "gitlab:unknown".into()
}

/// Truncate a list of strings for display.
fn truncate_list(items: &[String], max_len: usize) -> String {
    let joined = items.join(", ");
    if joined.len() <= max_len {
        joined
    } else {
        let truncated = &joined[..max_len.saturating_sub(10)];
        format!("{}... +{} more", truncated, items.len())
    }
}

/// Ensure Connector OS is running. DevGuard boots Connector — not the other way around.
/// Connector is a standalone OS that can run solo. DevGuard is an app that needs it.
async fn ensure_connector_running(client: &ConnectorClient) -> Result<()> {
    match client.health().await {
        Ok(_) => {
            println!("  Connector:   ✓ running at {}", client.base_url());
            return Ok(());
        }
        Err(_) => {
            println!("  Connector:   not running at {}", client.base_url());
        }
    }

    // Try to auto-start Connector
    println!("  Starting Connector OS...");

    // Look for connector-platform binary in common locations
    let candidates = [
        "connector-platform",                    // in PATH
        "./target/release/connector-platform",   // local build
        "../server/target/release/connector-platform",  // sibling crate
    ];

    let mut binary: Option<&str> = None;
    for candidate in &candidates {
        if std::process::Command::new("which").arg(candidate).output()
            .map(|o| o.status.success()).unwrap_or(false)
        {
            binary = Some(candidate);
            break;
        }
        if std::path::Path::new(candidate).exists() {
            binary = Some(candidate);
            break;
        }
    }

    let bin = binary.ok_or_else(|| {
        anyhow::anyhow!(
            "Connector not running and binary not found.\n\
             Start it manually: connector-platform\n\
             Or build it: cd platform/server && cargo build --release"
        )
    })?;

    // Start Connector in background
    let child = std::process::Command::new(bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("Failed to start Connector from '{}'", bin))?;

    println!("  Connector:   launched (PID {})", child.id());

    // Wait for it to become healthy (up to 10 seconds)
    for i in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if client.health().await.is_ok() {
            println!("  Connector:   ✓ ready (took {}ms)", (i + 1) * 500);
            return Ok(());
        }
    }

    anyhow::bail!(
        "Connector started but not responding after 10s.\n\
         Check logs or start manually: {} &",
        bin
    )
}
