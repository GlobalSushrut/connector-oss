//! `devguard policy` — validate, show, and matrix for RBAC policies.

use anyhow::Result;
use crate::config::DevGuardConfig;

pub async fn validate(path: &str, verbose: bool) -> Result<()> {
    let config = DevGuardConfig::load(path)?;
    let errors = config.validate();

    if errors.is_empty() {
        let roles = config.roles.len();
        let assignments = config.assignments.len();
        let fingerprint = config.fingerprint();
        let has_catchall = config.assignments.iter().any(|a| a.identity == "*");

        println!("✓ {} roles defined", roles);
        println!("✓ {} assignments resolved", assignments);
        if has_catchall {
            println!("✓ Catch-all assignment present");
        }
        println!("✓ Policy fingerprint: {}...{}", &fingerprint[..8], &fingerprint[fingerprint.len()-8..]);

        // Warnings
        for (name, role) in &config.roles {
            if role.secrets.is_default() || role.secrets.is_none() {
                // Only warn if clearance > 1
                if role.clearance > 1 {
                    println!("⚠ Role '{}' has no secret access — intentional?", name);
                }
            }
        }

        if config.enforcement.mode == "audit_only" {
            println!("⚠ Enforcement mode is 'audit_only' — no blocking.");
        }

        if verbose {
            println!("\nVerbose checks:");
            println!("  [PASS] YAML parse");
            println!("  [PASS] role definitions ({})", config.roles.len());
            println!("  [PASS] assignment references");
            println!("  [PASS] inheritance references");
            println!("  [PASS] catch-all/default role coverage");
            println!("  [PASS] fingerprint generated");
        }
        println!("\nPolicy is valid.");
    } else {
        eprintln!("Policy errors in {}:", path);
        for e in &errors {
            eprintln!("  ✗ {}", e);
        }
        if verbose {
            eprintln!("\nVerbose checks:");
            eprintln!("  [PASS] YAML parse");
            eprintln!("  [FAIL] semantic validation ({} issue(s))", errors.len());
        }
        std::process::exit(1);
    }

    Ok(())
}

pub async fn show(identity: &str, tool: &str, config_path: &str) -> Result<()> {
    let config = DevGuardConfig::load(config_path)?;

    let tool_key = tool.to_lowercase().replace('-', "_");
    match config.resolve_role(identity, &tool_key) {
        Some(resolved) => {
            let rc = &resolved.config;
            println!("Effective permissions for {} on {}:\n", identity, tool);
            println!("  Role:           {}", resolved.role_name);
            println!("  Clearance:      {}", rc.clearance);

            println!("\n  ── Files ──");
            println!("  Visible:        {}", if rc.files.read.is_empty() { "none".into() } else { rc.files.read.join(", ") });
            println!("  Writable:       {}", if rc.files.write.is_empty() { "none".into() } else { rc.files.write.join(", ") });
            println!("  Hidden:         {}", if rc.files.hidden.is_empty() { "none".into() } else { rc.files.hidden.join(", ") });
            if !rc.files.read_only.is_empty() {
                println!("  Read-only:      {}", rc.files.read_only.join(", "));
            }

            println!("\n  ── Commands ──");
            println!("  Allowed:        {}", if rc.execution.allow.is_empty() { "none".into() } else { rc.execution.allow.join(", ") });
            println!("  Denied:         {}", if rc.execution.deny.is_empty() { "none".into() } else { rc.execution.deny.join(", ") });
            if !rc.execution.require_approval.is_empty() {
                println!("  Need approval:  {}", rc.execution.require_approval.join(", "));
            }

            println!("\n  ── Branches ──");
            println!("  Allowed:        {}", if rc.branches.allow.is_empty() { "none".into() } else { rc.branches.allow.join(", ") });
            if !rc.branches.deny.is_empty() {
                println!("  Denied:         {}", rc.branches.deny.join(", "));
            }

            println!("\n  ── Secrets ──");
            if rc.secrets.allowed_via_broker.is_empty() {
                println!("  Access:         NONE");
            } else {
                println!("  Via broker:     {}", rc.secrets.allowed_via_broker.join(", "));
            }

            println!("\n  ── Network ──");
            println!("  Allowed hosts:  {}", if rc.network.allow.is_empty() { "none".into() } else { rc.network.allow.join(", ") });

            println!("\n  ── Budget ──");
            println!("  Tokens/task:    {}", rc.budget.max_tokens_per_task);
            println!("  Cost/day:       ${:.2}", rc.budget.max_cost_usd_per_day);
            println!("  Model:          {}", if rc.budget.model.is_empty() { "default" } else { &rc.budget.model });
        }
        None => {
            eprintln!("No role assignment found for identity '{}' with tool '{}'.", identity, tool);
            if !config.default_role.is_empty() {
                eprintln!("Default role '{}' would apply.", config.default_role);
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

pub async fn matrix(config_path: &str) -> Result<()> {
    let config = DevGuardConfig::load(config_path)?;

    println!("Access Matrix — {}\n", config_path);
    println!(
        "{:<20} {:<12} {:<12} {:<28} {:<28}",
        "IDENTITY", "TOOL", "ROLE", "READ PATHS", "WRITE PATHS"
    );
    println!("{}", "─".repeat(108));

    for assignment in &config.assignments {
        let tools = if assignment.tools.is_empty() {
            vec!["*".to_string()]
        } else {
            assignment.tools.clone()
        };
        for tool in tools {
            let resolved = config.resolve_role(&assignment.identity, &tool);
            let (role_name, read_paths, write_paths) = if let Some(rr) = resolved {
                (
                    rr.role_name,
                    truncate_list(&rr.config.files.read, 26),
                    truncate_list(&rr.config.files.write, 26),
                )
            } else {
                ("?".to_string(), "?".to_string(), "?".to_string())
            };
            let identity_display = if assignment.identity.len() > 18 {
                format!("{}...", &assignment.identity[..16])
            } else {
                assignment.identity.clone()
            };
            println!(
                "{:<20} {:<12} {:<12} {:<28} {:<28}",
                identity_display, tool, role_name, read_paths, write_paths
            );
        }
    }

    println!();
    Ok(())
}

fn truncate_list(values: &[String], max_len: usize) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    let joined = values.join(", ");
    if joined.len() <= max_len {
        joined
    } else {
        format!("{}...", &joined[..max_len.saturating_sub(3)])
    }
}
