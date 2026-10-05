//! Man Pages / Help System for connectorctl
//!
//! Provides detailed help documentation for all connectorctl commands.
//! Modeled on Unix man pages with sections for synopsis, description,
//! options, examples, and see also.

use std::collections::HashMap;

/// Help page for a command
#[derive(Debug, Clone)]
pub struct HelpPage {
    /// Command name
    pub name: &'static str,
    /// Short description (one line)
    pub short: &'static str,
    /// Synopsis (usage pattern)
    pub synopsis: &'static str,
    /// Full description
    pub description: &'static str,
    /// Options
    pub options: &'static [(&'static str, &'static str)],
    /// Examples
    pub examples: &'static [(&'static str, &'static str)],
    /// See also (related commands)
    pub see_also: &'static [&'static str],
    /// Exit codes
    pub exit_codes: &'static [(i32, &'static str)],
}

/// Help system registry
pub struct HelpSystem {
    pages: HashMap<&'static str, HelpPage>,
}

impl HelpSystem {
    pub fn new() -> Self {
        let mut pages = HashMap::new();
        
        // Register all help pages
        pages.insert("start", HELP_START);
        pages.insert("stop", HELP_STOP);
        pages.insert("restart", HELP_RESTART);
        pages.insert("status", HELP_STATUS);
        pages.insert("health", HELP_HEALTH);
        pages.insert("doctor", HELP_DOCTOR);
        pages.insert("logs", HELP_LOGS);
        pages.insert("agents", HELP_AGENTS);
        pages.insert("inspect", HELP_INSPECT);
        pages.insert("deploy", HELP_DEPLOY);
        pages.insert("bootstrap", HELP_BOOTSTRAP);
        pages.insert("backup", HELP_BACKUP);
        pages.insert("restore", HELP_RESTORE);
        pages.insert("config", HELP_CONFIG);
        pages.insert("version", HELP_VERSION);
        
        Self { pages }
    }

    /// Get help for a command
    pub fn get(&self, command: &str) -> Option<&HelpPage> {
        self.pages.get(command)
    }

    /// List all commands
    pub fn list_commands(&self) -> Vec<(&'static str, &'static str)> {
        let mut cmds: Vec<_> = self.pages.values()
            .map(|p| (p.name, p.short))
            .collect();
        cmds.sort_by_key(|(name, _)| *name);
        cmds
    }

    /// Format help page for display
    pub fn format(&self, page: &HelpPage, use_colors: bool) -> String {
        let (bold, reset, cyan, dim, yellow) = if use_colors {
            ("\x1b[1m", "\x1b[0m", "\x1b[36m", "\x1b[2m", "\x1b[33m")
        } else {
            ("", "", "", "", "")
        };

        let mut out = String::new();

        // NAME
        out.push_str(&format!("{}NAME{}\n", cyan, reset));
        out.push_str(&format!("    {}{}{} — {}\n\n", bold, page.name, reset, page.short));

        // SYNOPSIS
        out.push_str(&format!("{}SYNOPSIS{}\n", cyan, reset));
        out.push_str(&format!("    {}\n\n", page.synopsis));

        // DESCRIPTION
        out.push_str(&format!("{}DESCRIPTION{}\n", cyan, reset));
        for line in page.description.lines() {
            out.push_str(&format!("    {}\n", line));
        }
        out.push('\n');

        // OPTIONS
        if !page.options.is_empty() {
            out.push_str(&format!("{}OPTIONS{}\n", cyan, reset));
            for (opt, desc) in page.options {
                out.push_str(&format!("    {}{}{}\n", bold, opt, reset));
                out.push_str(&format!("        {}\n", desc));
            }
            out.push('\n');
        }

        // EXAMPLES
        if !page.examples.is_empty() {
            out.push_str(&format!("{}EXAMPLES{}\n", cyan, reset));
            for (cmd, desc) in page.examples {
                out.push_str(&format!("    {}# {}{}\n", dim, desc, reset));
                out.push_str(&format!("    {}{}{}\n\n", yellow, cmd, reset));
            }
        }

        // EXIT CODES
        if !page.exit_codes.is_empty() {
            out.push_str(&format!("{}EXIT CODES{}\n", cyan, reset));
            for (code, desc) in page.exit_codes {
                out.push_str(&format!("    {}{}{}  {}\n", bold, code, reset, desc));
            }
            out.push('\n');
        }

        // SEE ALSO
        if !page.see_also.is_empty() {
            out.push_str(&format!("{}SEE ALSO{}\n", cyan, reset));
            out.push_str(&format!("    {}\n", page.see_also.join(", ")));
        }

        out
    }
}

impl Default for HelpSystem {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Help Pages
// =============================================================================

const HELP_START: HelpPage = HelpPage {
    name: "start",
    short: "Start the Connector Node",
    synopsis: "connectorctl start [--foreground]",
    description: "\
Start the Connector Node daemon. By default, the node is started as a
background service using systemd (if available) or as a detached process.

The node will go through its boot sequence, initializing the memory kernel,
loading policies, and starting the API server. Use 'connectorctl status'
to check if the node is ready.",
    options: &[
        ("-f, --foreground", "Run in foreground (don't daemonize). Useful for debugging."),
    ],
    examples: &[
        ("connectorctl start", "Start node as background service"),
        ("connectorctl start --foreground", "Start node in foreground for debugging"),
    ],
    see_also: &["stop", "restart", "status"],
    exit_codes: &[
        (0, "Node started successfully"),
        (1, "Failed to start node"),
    ],
};

const HELP_STOP: HelpPage = HelpPage {
    name: "stop",
    short: "Stop the Connector Node",
    synopsis: "connectorctl stop",
    description: "\
Stop the Connector Node daemon gracefully. The node will:
1. Stop accepting new requests
2. Drain existing connections (30s timeout)
3. Checkpoint agent state
4. Close storage handles
5. Exit cleanly

If systemd is available, uses 'systemctl stop'. Otherwise, sends SIGTERM.",
    options: &[],
    examples: &[
        ("connectorctl stop", "Stop the running node"),
    ],
    see_also: &["start", "restart", "status"],
    exit_codes: &[
        (0, "Node stopped successfully"),
        (1, "No node running or stop failed"),
    ],
};

const HELP_RESTART: HelpPage = HelpPage {
    name: "restart",
    short: "Restart the Connector Node",
    synopsis: "connectorctl restart [--foreground]",
    description: "\
Stop and start the Connector Node. Equivalent to running 'stop' followed
by 'start'. Waits 2 seconds between stop and start to allow cleanup.",
    options: &[
        ("-f, --foreground", "Start in foreground after restart"),
    ],
    examples: &[
        ("connectorctl restart", "Restart the node"),
    ],
    see_also: &["start", "stop"],
    exit_codes: &[
        (0, "Node restarted successfully"),
        (1, "Restart failed"),
    ],
};

const HELP_STATUS: HelpPage = HelpPage {
    name: "status",
    short: "Show node status",
    synopsis: "connectorctl status",
    description: "\
Display the current status of the Connector Node, including:
- Service state (via systemd if available)
- API reachability
- Version information
- Ready state
- Uptime",
    options: &[],
    examples: &[
        ("connectorctl status", "Show current node status"),
    ],
    see_also: &["health", "doctor"],
    exit_codes: &[
        (0, "Status retrieved successfully"),
    ],
};

const HELP_HEALTH: HelpPage = HelpPage {
    name: "health",
    short: "Quick health check",
    synopsis: "connectorctl health",
    description: "\
Perform a quick health check on the Connector Node. Queries the /health
endpoint and reports whether the node is healthy and ready to serve requests.

This command is suitable for use in scripts and monitoring systems.",
    options: &[],
    examples: &[
        ("connectorctl health", "Check if node is healthy"),
        ("connectorctl health && echo 'OK'", "Use in scripts"),
    ],
    see_also: &["status", "doctor"],
    exit_codes: &[
        (0, "Node is healthy and ready"),
        (1, "Node is not ready"),
        (2, "Node is unreachable"),
    ],
};

const HELP_DOCTOR: HelpPage = HelpPage {
    name: "doctor",
    short: "Full diagnostic report",
    synopsis: "connectorctl doctor [--verbose]",
    description: "\
Run a comprehensive diagnostic check on the Connector Node and its
environment. Checks include:
- API connectivity
- Node readiness
- LLM configuration
- Data directory
- Environment variables (with --verbose)",
    options: &[
        ("-v, --verbose", "Show additional environment details"),
    ],
    examples: &[
        ("connectorctl doctor", "Run diagnostics"),
        ("connectorctl doctor --verbose", "Run with extra details"),
    ],
    see_also: &["health", "status", "logs"],
    exit_codes: &[
        (0, "All checks passed"),
        (1, "Warnings found"),
        (2, "Errors found"),
    ],
};

const HELP_LOGS: HelpPage = HelpPage {
    name: "logs",
    short: "View node logs",
    synopsis: "connectorctl logs [--follow] [-n LINES]",
    description: "\
View the Connector Node logs. Uses journalctl if systemd is available,
otherwise reads from the log file directly.

Logs include boot messages, API requests, agent activity, and errors.",
    options: &[
        ("-f, --follow", "Follow log output (like tail -f)"),
        ("-n, --lines LINES", "Number of lines to show (default: 50)"),
    ],
    examples: &[
        ("connectorctl logs", "Show last 50 log lines"),
        ("connectorctl logs -f", "Follow logs in real-time"),
        ("connectorctl logs -n 100", "Show last 100 lines"),
    ],
    see_also: &["status", "doctor"],
    exit_codes: &[
        (0, "Logs displayed successfully"),
        (1, "Failed to read logs"),
    ],
};

const HELP_AGENTS: HelpPage = HelpPage {
    name: "agents",
    short: "List running agents",
    synopsis: "connectorctl agents",
    description: "\
List all agents currently running on the Connector Node. Shows:
- Agent PID (process identifier)
- Status (running, suspended, etc.)
- Memory usage (packet count)
- Agent name",
    options: &[],
    examples: &[
        ("connectorctl agents", "List all agents"),
    ],
    see_also: &["inspect", "deploy"],
    exit_codes: &[
        (0, "Agents listed successfully"),
        (1, "Failed to fetch agents"),
    ],
};

const HELP_INSPECT: HelpPage = HelpPage {
    name: "inspect",
    short: "Inspect an agent",
    synopsis: "connectorctl inspect <agent-pid>",
    description: "\
Display detailed information about a specific agent, including:
- Agent metadata (name, DID, role)
- Current phase and status
- Memory usage and limits
- Active sessions
- Tool permissions
- Recent activity",
    options: &[],
    examples: &[
        ("connectorctl inspect pid:abc123", "Inspect agent by PID"),
    ],
    see_also: &["agents", "deploy"],
    exit_codes: &[
        (0, "Agent details displayed"),
        (1, "Agent not found or error"),
    ],
};

const HELP_DEPLOY: HelpPage = HelpPage {
    name: "deploy",
    short: "Deploy an agent manifest",
    synopsis: "connectorctl deploy <manifest.yaml> [--dry-run]",
    description: "\
Deploy an agent from a YAML manifest file. The manifest defines:
- Agent identity and role
- Resource limits
- Tool permissions
- Initial configuration

Use --dry-run to validate the manifest without deploying.",
    options: &[
        ("--dry-run", "Validate manifest without deploying"),
    ],
    examples: &[
        ("connectorctl deploy agent.yaml", "Deploy an agent"),
        ("connectorctl deploy agent.yaml --dry-run", "Validate only"),
    ],
    see_also: &["agents", "inspect"],
    exit_codes: &[
        (0, "Agent deployed successfully"),
        (1, "Deployment failed"),
    ],
};

const HELP_BOOTSTRAP: HelpPage = HelpPage {
    name: "bootstrap",
    short: "Migrate legacy secret env vars into the kernel vault",
    synopsis: "connectorctl bootstrap [--apply]",
    description: "\
Reads non-empty legacy API-key style environment variables and POSTs each value to
POST /api/v1/infra/vault/secrets with owner_pid kernel and secret_id bootstrap/env/<VAR>.

Without --apply, only prints what would be migrated and shows unset hints.
CONNECTOR_API_KEY is never migrated (it authenticates this CLI).

After --apply, remove the variables from systemd units, compose files, or shell profiles.",
    options: &[
        ("--apply", "Perform vault writes (default is dry-run)"),
    ],
    examples: &[
        ("connectorctl bootstrap", "Preview migration"),
        ("connectorctl bootstrap --apply", "Store secrets in vault"),
    ],
    see_also: &["health", "status", "boot"],
    exit_codes: &[
        (0, "Success or nothing to migrate"),
        (1, "Node unreachable, vault error, or unknown flag"),
    ],
};

const HELP_BACKUP: HelpPage = HelpPage {
    name: "backup",
    short: "Create a trust-domain backup",
    synopsis: "connectorctl backup [--output FILE]",
    description: "\
Fail-closed tar of CONNECTOR_DATA_DIR plus a .manifest.json (sha256 file list,
node version, env key refs). Does not include JWT/audit/CFNI secrets — restore
those from your vault. See docs/TRUST_DOMAIN_BACKUP.md.",
    options: &[
        ("-o, --output FILE", "Output file (default: connector-backup.tar.gz)"),
    ],
    examples: &[
        ("connectorctl backup", "Create backup with default name"),
        ("connectorctl backup -o /backups/daily.tar.gz", "Custom output path"),
    ],
    see_also: &["restore", "node-upgrade"],
    exit_codes: &[
        (0, "Backup created successfully"),
        (1, "Backup failed"),
    ],
};

const HELP_RESTORE: HelpPage = HelpPage {
    name: "restore",
    short: "Restore from trust-domain backup",
    synopsis: "connectorctl restore <backup.tar.gz> [--yes]",
    description: "\
Restore CONNECTOR_DATA_DIR from a backup. Requires matching .manifest.json.
Refuses if /health is up (stop the node first). Fail-closed on tar errors.",
    options: &[
        ("--yes, -y", "Skip interactive confirmation"),
    ],
    examples: &[
        ("connectorctl restore connector-backup.tar.gz", "Restore from backup"),
    ],
    see_also: &["backup", "stop", "doctor"],
    exit_codes: &[
        (0, "Restore completed successfully"),
        (1, "Restore failed or aborted"),
    ],
};

const HELP_CONFIG: HelpPage = HelpPage {
    name: "config",
    short: "Configuration commands",
    synopsis: "connectorctl config <validate|show>",
    description: "\
Manage Connector Node configuration.

Subcommands:
  validate    Check configuration for errors
  show        Display current configuration values",
    options: &[],
    examples: &[
        ("connectorctl config validate", "Validate configuration"),
        ("connectorctl config show", "Show current config"),
    ],
    see_also: &["doctor", "status"],
    exit_codes: &[
        (0, "Command succeeded"),
        (1, "Validation failed or error"),
    ],
};

const HELP_VERSION: HelpPage = HelpPage {
    name: "version",
    short: "Show version",
    synopsis: "connectorctl version",
    description: "Display the connectorctl version number.",
    options: &[],
    examples: &[
        ("connectorctl version", "Show version"),
    ],
    see_also: &["status"],
    exit_codes: &[
        (0, "Version displayed"),
    ],
};

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_system() {
        let help = HelpSystem::new();
        
        assert!(help.get("start").is_some());
        assert!(help.get("stop").is_some());
        assert!(help.get("nonexistent").is_none());
    }

    #[test]
    fn test_list_commands() {
        let help = HelpSystem::new();
        let cmds = help.list_commands();
        
        assert!(cmds.len() >= 10);
        assert!(cmds.iter().any(|(name, _)| *name == "start"));
    }

    #[test]
    fn test_format_help() {
        let help = HelpSystem::new();
        let page = help.get("start").unwrap();
        let formatted = help.format(page, false);
        
        assert!(formatted.contains("NAME"));
        assert!(formatted.contains("SYNOPSIS"));
        assert!(formatted.contains("DESCRIPTION"));
        assert!(formatted.contains("start"));
    }
}
