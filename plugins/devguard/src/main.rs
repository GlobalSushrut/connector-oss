//! DevGuard — Military-grade governance for AI coding agents.
//!
//! DevGuard is an APPLICATION that runs on top of the Connector OS.
//! It communicates with Connector exclusively via HTTP APIs.
//! DevGuard never links against connector-engine or any Connector crate.
//!
//! Connector = Operating System (agents, gateway, audit, memory, secrets, trust).
//! DevGuard = Application (CLI, adapters, policy, risk, approval, RBAC).

use clap::{Args, Parser, Subcommand};

mod action;
mod adapter;
mod approval;
mod commands;
mod config;
mod connector_client;
mod guard_patterns;
mod fs_guard;
mod enforce;
mod output;
mod policy;
mod risk;
mod session;
mod services;

#[derive(Parser)]
#[command(name = "devguard")]
#[command(about = "Policy checks and measured controls for coding agents")]
#[command(version)]
struct Cli {
    /// Connector API base URL
    #[arg(long, env = "CONNECTOR_URL", default_value = "http://localhost:9091")]
    connector_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize devguard.yaml in the current workspace
    Init {
        /// Initialize with team RBAC mode
        #[arg(long)]
        team: bool,
        /// Identity provider (github, gitlab, okta, ldap, local)
        #[arg(long, default_value = "local")]
        provider: String,
        /// Organization name (for github/gitlab)
        #[arg(long)]
        org: Option<String>,
    },

    /// Connect a coding tool under DevGuard governance
    Connect {
        /// Tool to connect (claude-code, cursor, windsurf, aider, kiro, generic)
        tool: Option<String>,
        /// Role override (default: resolved from devguard.yaml assignments)
        #[arg(long)]
        role: Option<String>,
        /// Enable local cage (git hooks + FS watchdog + exec wrapper; not a kernel overlay)
        #[arg(long)]
        cage: bool,
        /// Path to devguard.yaml
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
        /// Show what would be written without writing
        #[arg(long)]
        dry_run: bool,
        /// List connected tools and status
        #[arg(long)]
        list: bool,
    },

    /// Bind a local process via native origin-binding APIs, then exec (default: cursor)
    Run {
        /// Request birth-controlled workload registration (cgroup/pidfd confinement is M1 WIP)
        #[arg(long)]
        birth_controlled: bool,
        /// Intelligence contract ref (default: dev-agent-v1)
        #[arg(long)]
        contract: Option<String>,
        /// Optional legacy agent_pid for native_compat mapping
        #[arg(long)]
        agent_pid: Option<String>,
        /// Bind software/workload/intelligence then stop before exec
        #[arg(long)]
        dry_bind: bool,
        /// Command to exec after binding (default: cursor). Use `--` before flags belonging to the child.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Guided one-command startup wizard (git + tool + unlock + role)
    Start,

    /// Live DevGuard dashboard (refreshing status view)
    Dashboard(DashboardArgs),

    /// Serve extension status endpoint for IDE plugins
    ServeStatus(ServeStatusArgs),

    /// Internal long-running monitor daemon (spawned by start)
    #[command(hide = true)]
    Monitor {
        #[arg(long)]
        session: String,
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },

    /// Pre-flight check: test if an action is allowed by policy (offline, no server needed)
    Check {
        #[command(subcommand)]
        action: CheckCommands,
    },

    /// Show status of active DevGuard sessions
    Status {
        /// Session ID (show specific session, or all if omitted)
        session: Option<String>,
    },

    /// Disconnect a governed session
    Disconnect {
        /// Session ID to disconnect
        session: String,
    },

    /// Show trace for a session or agent
    Trace {
        /// Subject (session ID or agent PID)
        subject: String,
    },

    /// Explain a session or agent's behavior
    Explain {
        /// Subject (session ID or agent PID)
        subject: String,
    },

    /// Show proof chain for a session
    Prove {
        /// Subject (session ID or agent PID)
        subject: String,
    },

    /// Manage approvals
    Approvals {
        #[command(subcommand)]
        action: ApprovalCommands,
    },

    /// Policy management
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },
    /// Config editor and validator
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Health check — verify Connector is running and DevGuard is configured
    Doctor,

    /// Team assignment management
    Team {
        #[command(subcommand)]
        action: TeamCommands,
    },

    /// Layered workstation controls for supported editor, git, and shell channels
    Cage {
        #[command(subcommand)]
        action: CageCommands,
    },
}

#[derive(Subcommand)]
enum CageCommands {
    /// Activate the cage — install git hooks, filesystem watchdog, exec wrapper, file perms
    Start {
        /// Path to devguard.yaml
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
        /// Optional devguard binary name/path used inside installed git hooks
        #[arg(long)]
        path: Option<String>,
    },
    /// Deactivate the cage
    Stop,
    /// Show cage status
    Status {
        /// Run active verification probes against temporary protected files
        #[arg(long)]
        verify: bool,
    },
    /// Internal watchdog daemon (spawned by `cage start`)
    #[command(hide = true)]
    Watchdog {
        /// Workspace path
        #[arg(long)]
        workspace: String,
        /// Path to devguard.yaml
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
}

#[derive(Subcommand)]
enum CheckCommands {
    /// Check if a file operation is allowed
    File {
        /// Operation: read, write, delete
        operation: String,
        /// File path
        path: String,
        /// Identity (default: auto-detect)
        #[arg(long, default_value = "auto")]
        identity: String,
        /// Tool context
        #[arg(long, default_value = "claude_code")]
        tool: String,
        /// Path to devguard.yaml
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
    /// Check if a command is allowed
    Exec {
        /// Shell command to check
        command: String,
        #[arg(long, default_value = "auto")]
        identity: String,
        #[arg(long, default_value = "claude_code")]
        tool: String,
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
    /// Check if a git operation is allowed
    Git {
        /// Git operation: push, commit, merge, rebase, branch, tag
        operation: String,
        /// Target branch/ref (or remote for push)
        target: String,
        /// Extra arg (e.g. branch when target is remote: `git push origin main`)
        extra: Option<String>,
        #[arg(long, default_value = "auto")]
        identity: String,
        #[arg(long, default_value = "claude_code")]
        tool: String,
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
    /// Check if a secret can be accessed
    Secret {
        /// Secret key name
        key: String,
        #[arg(long, default_value = "auto")]
        identity: String,
        #[arg(long, default_value = "claude_code")]
        tool: String,
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
}

#[derive(Subcommand)]
enum ApprovalCommands {
    /// List pending approvals
    List {
        /// Filter by session
        #[arg(long)]
        session: Option<String>,
    },
    /// Approve a pending action
    Approve {
        /// Approval ID
        id: String,
    },
    /// Reject a pending action
    Reject {
        /// Approval ID
        id: String,
        /// Reason for rejection
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Validate devguard.yaml
    Validate {
        /// Path to devguard.yaml
        #[arg(default_value = "devguard.yaml")]
        path: String,
        /// Print PASS/FAIL checks with reasons
        #[arg(long)]
        verbose: bool,
    },
    /// Show effective permissions for an identity + tool
    Show {
        /// Identity (e.g. github:alice)
        #[arg(long)]
        identity: String,
        /// Tool (e.g. claude_code)
        #[arg(long)]
        tool: String,
        /// Path to devguard.yaml
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
    /// Show access matrix for all assignments
    Matrix {
        /// Path to devguard.yaml
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Open devguard.yaml in $EDITOR and validate on exit
    Edit {
        /// Path to devguard.yaml
        #[arg(default_value = "devguard.yaml")]
        path: String,
    },
    /// Validate devguard.yaml
    Validate {
        /// Path to devguard.yaml
        #[arg(default_value = "devguard.yaml")]
        path: String,
        /// Print PASS/FAIL checks with reasons
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum TeamCommands {
    /// Add a team identity assignment
    Add {
        identity: String,
        #[arg(long)]
        role: String,
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
    /// List team assignments
    List {
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
    /// Audit effective member path access
    Audit {
        #[arg(long, default_value = "devguard.yaml")]
        config: String,
    },
}

#[derive(Args)]
struct DashboardArgs {
    /// Session ID to follow (if omitted, shows active sessions)
    #[arg(long)]
    session: Option<String>,
    /// Refresh interval in seconds
    #[arg(long, default_value_t = 2)]
    interval: u64,
    /// Render one frame and exit
    #[arg(long)]
    once: bool,
}

#[derive(Args)]
struct ServeStatusArgs {
    /// Session ID hint for status view
    #[arg(long)]
    session: Option<String>,
    /// Bind host
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Bind port
    #[arg(long, default_value_t = 7788)]
    port: u16,
    /// Path to devguard.yaml
    #[arg(long, default_value = "devguard.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    connector_plugin_handshake::apply_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

    let cli = Cli::parse();
    let client = connector_client::ConnectorClient::new(&cli.connector_url);

    match cli.command {
        Commands::Init { team, provider, org } => {
            commands::init::run(team, &provider, org.as_deref()).await
        }
        Commands::Connect { tool, role, cage, config, dry_run, list } => {
            commands::connect::run(&client, tool.as_deref(), role.as_deref(), cage, &config, dry_run, list)
                .await
                .map(|_| ())
        }
        Commands::Run {
            birth_controlled,
            contract,
            agent_pid,
            dry_bind,
            command,
        } => {
            commands::run::run(
                &cli.connector_url,
                commands::run::RunArgs {
                    birth_controlled,
                    contract,
                    agent_pid,
                    dry_bind,
                    command,
                },
            )
            .await
        }
        Commands::Start => {
            commands::start::run(&client).await
        }
        Commands::Dashboard(args) => {
            commands::dashboard::run(&client, args.session.as_deref(), args.interval, args.once).await
        }
        Commands::ServeStatus(args) => {
            commands::status_api::serve(client.clone(), args.session, &args.host, args.port, args.config).await
        }
        Commands::Monitor { session, interval } => {
            commands::monitor::run(&client, &session, interval).await
        }
        Commands::Check { action } => {
            match action {
                CheckCommands::File { operation, path, identity, tool, config } => {
                    commands::check::run_file(&operation, &path, &config, &identity, &tool).await
                }
                CheckCommands::Exec { command, identity, tool, config } => {
                    commands::check::run_exec(&command, &config, &identity, &tool).await
                }
                CheckCommands::Git { operation, target, extra, identity, tool, config } => {
                    // If extra is provided: target=remote, extra=branch (e.g. `push origin main`)
                    let effective_target = extra.as_deref().unwrap_or(&target);
                    commands::check::run_git(&operation, effective_target, &config, &identity, &tool).await
                }
                CheckCommands::Secret { key, identity, tool, config } => {
                    commands::check::run_secret(&key, &config, &identity, &tool).await
                }
            }
        }
        Commands::Status { session } => {
            commands::status::run(&client, session.as_deref()).await
        }
        Commands::Disconnect { session } => {
            commands::disconnect::run(&client, &session).await
        }
        Commands::Trace { subject } => {
            commands::trace::run(&client, &subject).await
        }
        Commands::Explain { subject } => {
            commands::explain::run(&client, &subject).await
        }
        Commands::Prove { subject } => {
            commands::prove::run(&client, &subject).await
        }
        Commands::Approvals { action } => {
            match action {
                ApprovalCommands::List { session } => {
                    commands::approvals::list(&client, session.as_deref()).await
                }
                ApprovalCommands::Approve { id } => {
                    commands::approvals::approve(&client, &id).await
                }
                ApprovalCommands::Reject { id, reason } => {
                    commands::approvals::reject(&client, &id, reason.as_deref()).await
                }
            }
        }
        Commands::Policy { action } => {
            match action {
                PolicyCommands::Validate { path, verbose } => {
                    commands::policy::validate(&path, verbose).await
                }
                PolicyCommands::Show { identity, tool, config } => {
                    commands::policy::show(&identity, &tool, &config).await
                }
                PolicyCommands::Matrix { config } => {
                    commands::policy::matrix(&config).await
                }
            }
        }
        Commands::Config { action } => {
            match action {
                ConfigCommands::Edit { path } => commands::config_cmd::edit(&path).await,
                ConfigCommands::Validate { path, verbose } => {
                    commands::config_cmd::validate(&path, verbose).await
                }
            }
        }
        Commands::Doctor => {
            commands::doctor::run(&client).await
        }
        Commands::Team { action } => {
            match action {
                TeamCommands::Add { identity, role, tools, config } => {
                    commands::team::add(&identity, &role, &tools, &config).await
                }
                TeamCommands::List { config } => commands::team::list(&config).await,
                TeamCommands::Audit { config } => commands::team::audit(&config).await,
            }
        }
        Commands::Cage { action } => {
            match action {
                CageCommands::Start { config, path } => {
                    commands::cage::start(&config, path).await
                }
                CageCommands::Stop => {
                    commands::cage::stop().await
                }
                CageCommands::Status { verify } => {
                    commands::cage::status(verify).await
                }
                CageCommands::Watchdog { workspace, config } => {
                    commands::cage::run_watchdog(&workspace, &config).await
                }
            }
        }
    }
}
