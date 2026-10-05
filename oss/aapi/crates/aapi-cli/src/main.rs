//! AAPI CLI - Command-line interface for AAPI

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod commands;

#[derive(Parser)]
#[command(name = "aapi")]
#[command(author, version, about = "AAPI Command Line Interface", long_about = None)]
struct Cli {
    /// Gateway URL
    #[arg(short, long, default_value = "http://localhost:8080", env = "AAPI_GATEWAY_URL")]
    gateway: String,

    /// Output format (json, table, plain)
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the AAPI Gateway server
    Serve {
        /// Host to bind to
        #[arg(short = 'H', long, default_value = "0.0.0.0")]
        host: String,

        /// Port to bind to
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Database URL
        #[arg(short, long, default_value = "sqlite:aapi.db")]
        database: String,
    },

    /// Submit a VĀKYA request
    Submit {
        /// Actor principal ID
        #[arg(short, long)]
        actor: String,

        /// Resource ID
        #[arg(short, long)]
        resource: String,

        /// Action to perform
        #[arg(long)]
        action: String,

        /// Request body (JSON)
        #[arg(short, long, default_value = "{}")]
        body: String,

        /// Capability reference
        #[arg(short, long)]
        capability: Option<String>,

        /// TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: i64,
    },

    /// Get a VĀKYA by ID
    Get {
        /// VĀKYA ID
        vakya_id: String,

        /// Include effects
        #[arg(long)]
        effects: bool,

        /// Include receipt
        #[arg(long)]
        receipt: bool,
    },

    /// Query VĀKYA records
    Query {
        /// Filter by actor
        #[arg(long)]
        actor: Option<String>,

        /// Filter by action
        #[arg(long)]
        action: Option<String>,

        /// Filter by resource
        #[arg(long)]
        resource: Option<String>,

        /// Limit results
        #[arg(short, long, default_value = "10")]
        limit: u32,
    },

    /// Merkle tree operations
    Merkle {
        #[command(subcommand)]
        command: MerkleCommands,
    },

    /// Key management
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Health check
    Health,

    /// Manage live agents (kubectl-style operator commands)
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },

    /// Deploy an agent manifest to the platform
    Deploy {
        /// Path to agent.yaml manifest
        path: String,

        /// Validate only — no state mutation
        #[arg(long)]
        dry_run: bool,
    },

    /// Deploy an ephemeral agent, run once with input, then tear down
    Run {
        /// Path to agent.yaml manifest
        path: String,

        /// Input to pass to the agent
        #[arg(short, long)]
        input: String,
    },

    /// Show diff between live manifest and file on disk
    Diff {
        /// Agent name (as in metadata.name)
        name: String,

        /// Path to local file to compare against (defaults to <name>.yaml)
        #[arg(short, long)]
        file: Option<String>,
    },

    /// Upgrade an already deployed agent manifest to a new revision
    Upgrade {
        /// Path to agent.yaml manifest
        path: String,
    },

    /// Show revision history for a deployed agent
    History {
        /// Agent name (as in metadata.name)
        name: String,
    },

    /// Start the full platform server (AIOS-A7)
    Start {
        /// Host to bind to
        #[arg(short = 'H', long, default_value = "0.0.0.0")]
        host: String,

        /// Port to bind to
        #[arg(short, long, default_value = "9090")]
        port: u16,

        /// Path to connector.toml config file
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Scaffold ~/.connector/ data dir, default config, and signing key (AIOS-A7)
    Init {
        /// Directory to initialise (default: ~/.connector)
        #[arg(short, long)]
        dir: Option<String>,
    },

    /// Diagnose environment — checks config, signing key, port, LLM, server reachability (AIOS-B15)
    Doctor {
        /// Port to check availability for
        #[arg(short, long, default_value = "9090")]
        port: u16,
    },

    /// Generate shell completion scripts (AIOS-B16)
    Completions {
        /// Target shell: bash | zsh | fish | powershell
        shell: String,
    },
}

/// AIOS-A1: `aapi agent` subcommands — operator control plane for live agents.
#[derive(Subcommand)]
enum AgentCommands {
    /// List all live AgentControlBlocks (pid, status, phase, tokens, trust)
    Ps,

    /// Full ACB dump for a specific agent (JSON or table)
    Inspect {
        /// Agent PID
        pid: String,
    },

    /// Pause an agent (POST AgentSignal::Suspend)
    Pause {
        /// Agent PID
        pid: String,
    },

    /// Resume a paused agent (POST AgentSignal::Resume)
    Resume {
        /// Agent PID
        pid: String,
    },

    /// Terminate an agent (POST AgentSignal::Terminate)
    Kill {
        /// Agent PID
        pid: String,

        /// Reason for termination
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Tail the audit log for an agent
    Logs {
        /// Agent PID
        pid: String,

        /// Stream new entries as they arrive (polls every 1s)
        #[arg(short, long)]
        follow: bool,

        /// Number of most recent entries to show
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Live refreshing view of agents ranked by token usage (1s interval)
    Top,
}

#[derive(Subcommand)]
enum MerkleCommands {
    /// Get current Merkle root
    Root {
        /// Tree type (vakya, effect, receipt)
        #[arg(short, long, default_value = "vakya")]
        tree_type: String,
    },

    /// Get inclusion proof
    Proof {
        /// Tree type
        #[arg(short, long, default_value = "vakya")]
        tree_type: String,

        /// Leaf index
        #[arg(short, long)]
        index: i64,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new key pair
    Generate {
        /// Key purpose (signing, capability, receipt)
        #[arg(short, long, default_value = "signing")]
        purpose: String,
    },

    /// List keys
    List,

    /// Export public key
    Export {
        /// Key ID
        key_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| filter.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Serve { host, port, database } => {
            commands::serve::run(host, port, database).await?;
        }
        Commands::Submit { actor, resource, action, body, capability, ttl } => {
            commands::submit::run(&cli.gateway, actor, resource, action, body, capability, ttl, &cli.format).await?;
        }
        Commands::Get { vakya_id, effects, receipt } => {
            commands::get::run(&cli.gateway, vakya_id, effects, receipt, &cli.format).await?;
        }
        Commands::Query { actor, action, resource, limit } => {
            commands::query::run(&cli.gateway, actor, action, resource, limit, &cli.format).await?;
        }
        Commands::Merkle { command } => {
            match command {
                MerkleCommands::Root { tree_type } => {
                    commands::merkle::root(&cli.gateway, tree_type, &cli.format).await?;
                }
                MerkleCommands::Proof { tree_type, index } => {
                    commands::merkle::proof(&cli.gateway, tree_type, index, &cli.format).await?;
                }
            }
        }
        Commands::Keys { command } => {
            match command {
                KeyCommands::Generate { purpose } => {
                    commands::keys::generate(purpose, &cli.format)?;
                }
                KeyCommands::List => {
                    commands::keys::list(&cli.format)?;
                }
                KeyCommands::Export { key_id } => {
                    commands::keys::export(key_id, &cli.format)?;
                }
            }
        }
        Commands::Health => {
            commands::health::run(&cli.gateway, &cli.format).await?;
        }
        Commands::Start { host, port, config } => {
            commands::start::start(&host, port, config.as_deref()).await?;
        }
        Commands::Init { dir } => {
            commands::start::init(dir.as_deref()).await?;
        }
        Commands::Doctor { port } => {
            commands::doctor::run(&cli.gateway, port, &cli.format).await?;
        }
        Commands::Completions { shell } => {
            commands::completions::generate(&shell);
        }
        Commands::Deploy { path, dry_run } => {
            commands::deploy::deploy(&cli.gateway, &path, dry_run, &cli.format).await?;
        }
        Commands::Run { path, input } => {
            commands::deploy::run(&cli.gateway, &path, &input, &cli.format).await?;
        }
        Commands::Diff { name, file } => {
            commands::deploy::diff(&cli.gateway, &name, file.as_deref(), &cli.format).await?;
        }
        Commands::Upgrade { path } => {
            commands::deploy::upgrade(&cli.gateway, &path, &cli.format).await?;
        }
        Commands::History { name } => {
            commands::deploy::history(&cli.gateway, &name, &cli.format).await?;
        }
        Commands::Agent { command } => {
            match command {
                AgentCommands::Ps => {
                    commands::agent::ps(&cli.gateway, &cli.format).await?;
                }
                AgentCommands::Inspect { pid } => {
                    commands::agent::inspect(&cli.gateway, &pid, &cli.format).await?;
                }
                AgentCommands::Pause { pid } => {
                    commands::agent::pause(&cli.gateway, &pid).await?;
                }
                AgentCommands::Resume { pid } => {
                    commands::agent::resume(&cli.gateway, &pid).await?;
                }
                AgentCommands::Kill { pid, reason } => {
                    commands::agent::kill(&cli.gateway, &pid, reason).await?;
                }
                AgentCommands::Logs { pid, follow, limit } => {
                    commands::agent::logs(&cli.gateway, &pid, follow, limit, &cli.format).await?;
                }
                AgentCommands::Top => {
                    commands::agent::top(&cli.gateway).await?;
                }
            }
        }
    }

    Ok(())
}
