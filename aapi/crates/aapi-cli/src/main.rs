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
    }

    Ok(())
}
