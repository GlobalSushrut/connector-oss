use anyhow::{Context, Result};
use std::io::Write;

use crate::config::{Assignment, DevGuardConfig};

pub async fn add(identity: &str, role: &str, tools: &[String], config_path: &str) -> Result<()> {
    let mut cfg = DevGuardConfig::load(config_path)
        .with_context(|| format!("Failed to load {}", config_path))?;
    if !cfg.roles.contains_key(role) {
        anyhow::bail!("Role '{}' not found in {}", role, config_path);
    }
    let tool_list = if tools.is_empty() {
        vec!["*".to_string()]
    } else {
        tools.to_vec()
    };
    let exists = cfg.assignments.iter().any(|a| a.identity == identity && a.role == role && a.tools == tool_list);
    if exists {
        println!("Assignment already exists for {} -> {} ({:?})", identity, role, tool_list);
        return Ok(());
    }
    cfg.assignments.push(Assignment {
        identity: identity.to_string(),
        role: role.to_string(),
        tools: tool_list,
        overrides: None,
    });
    write_config(config_path, &cfg)?;
    println!("✓ Added team assignment: {} -> {}", identity, role);
    Ok(())
}

pub async fn list(config_path: &str) -> Result<()> {
    let cfg = DevGuardConfig::load(config_path)?;
    println!("{:<24} {:<14} {:<24}", "IDENTITY", "ROLE", "TOOLS");
    println!("{}", "─".repeat(66));
    for a in &cfg.assignments {
        println!(
            "{:<24} {:<14} {:<24}",
            truncate(&a.identity, 24),
            truncate(&a.role, 14),
            truncate(&a.tools.join(","), 24)
        );
    }
    Ok(())
}

pub async fn audit(config_path: &str) -> Result<()> {
    let cfg = DevGuardConfig::load(config_path)?;
    println!("{:<24} {:<12} {:<22} {:<22}", "IDENTITY", "TOOL", "READ", "WRITE");
    println!("{}", "─".repeat(86));
    for a in &cfg.assignments {
        let tools = if a.tools.is_empty() { vec!["*".to_string()] } else { a.tools.clone() };
        for t in tools {
            let resolved = cfg.resolve_role(&a.identity, &t);
            if let Some(r) = resolved {
                println!(
                    "{:<24} {:<12} {:<22} {:<22}",
                    truncate(&a.identity, 24),
                    truncate(&t, 12),
                    truncate(&r.config.files.read.join(","), 22),
                    truncate(&r.config.files.write.join(","), 22)
                );
            }
        }
    }
    Ok(())
}

pub fn collect_team_assignments_interactive(provider: &str, config: &mut DevGuardConfig) -> Result<()> {
    println!("\nTeam onboarding wizard");
    println!("Add members as <handle>:<role> (example: alice:senior). Press Enter to finish.");
    println!("Available roles: {}", config.roles.keys().cloned().collect::<Vec<_>>().join(", "));
    loop {
        print!("member> ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        let mut parts = line.split(':');
        let handle = parts.next().unwrap_or("").trim();
        let role = parts.next().unwrap_or("").trim();
        if handle.is_empty() || role.is_empty() {
            println!("  invalid format, expected <handle>:<role>");
            continue;
        }
        if !config.roles.contains_key(role) {
            println!("  role '{}' not found", role);
            continue;
        }
        let identity = format!("{}:{}", provider, handle);
        config.assignments.push(Assignment {
            identity,
            role: role.to_string(),
            tools: vec!["claude_code".into(), "cursor".into(), "windsurf".into()],
            overrides: None,
        });
        println!("  added {}", handle);
    }
    Ok(())
}

fn write_config(path: &str, cfg: &DevGuardConfig) -> Result<()> {
    let yaml = serde_yaml::to_string(cfg)?;
    std::fs::write(path, yaml)?;
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}...", &s[..n.saturating_sub(3)]) }
}
