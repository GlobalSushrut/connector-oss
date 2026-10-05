//! `cnktros` — Connector native developer CLI.
//!
//! Primary command graph for status, surfaces, channels, invoke, receipts,
//! bind and app packaging. Python Gloo is the primary authoring language;
//! this CLI is the control-plane front door. Production effects require a
//! signed `.cpkg` package digest (see package_gate).

mod app_build;

use clap::{Parser, Subcommand};
use connector_client::{ClientConfig, ConnectorClient};
use connector_native_contract::{PackagePin, RuntimeProfile};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "cnktros")]
#[command(about = "Connector native developer CLI — agents/tools package to signed .cpkg")]
#[command(version)]
struct Cli {
    /// Platform API base URL (default CONNECTOR_API_URL / http://127.0.0.1:9091)
    #[arg(long, env = "CONNECTOR_API_URL")]
    endpoint: Option<String>,

    /// Bearer API key (CONNECTOR_API_KEY). No silent dev-token.
    #[arg(long, env = "CONNECTOR_API_KEY")]
    api_key: Option<String>,

    /// Output JSON
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show software/workload/surface oriented status
    Status,
    /// Channel catalog
    Channels {
        #[command(subcommand)]
        action: Option<ChannelsCmd>,
    },
    /// Surface catalog
    Surfaces {
        #[command(subcommand)]
        action: Option<SurfacesCmd>,
    },
    /// Native invocation (requires --package-digest outside lab)
    Invoke {
        /// JSON file body for POST /native/invocations
        #[arg(long)]
        body: PathBuf,
        /// Package content digest (AppPackageV2)
        #[arg(long)]
        package_digest: Option<String>,
        /// Package id
        #[arg(long)]
        package_id: Option<String>,
        /// Package kind (app|plugin|adapter|workflow|toolset)
        #[arg(long, default_value = "app")]
        package_kind: String,
        /// Mark signature present on pin
        #[arg(long, default_value_t = true)]
        signed: bool,
        /// Load pin from `*.package.pin.json` produced by `app build`
        #[arg(long)]
        package_pin: Option<PathBuf>,
        /// Explicit lab unpackaged run (non-production only)
        #[arg(long)]
        lab: bool,
    },
    /// Fetch edge receipt
    Receipts {
        #[command(subcommand)]
        action: ReceiptsCmd,
    },
    /// Origin bind helpers
    Bind {
        #[command(subcommand)]
        action: BindCmd,
    },
    /// App / package workflows (Python Gloo primary; always emits .cpkg for production)
    App {
        #[command(subcommand)]
        action: AppCmd,
    },
    /// Package gate explain (local, no server)
    Package {
        #[command(subcommand)]
        action: PackageCmd,
    },
    /// Scoped configuration envelope snapshot (Phase 2 foundation)
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ChannelsCmd {
    List,
}

#[derive(Subcommand, Debug)]
enum SurfacesCmd {
    List,
    Probe { id: String },
}

#[derive(Subcommand, Debug)]
enum ReceiptsCmd {
    Get { operation_id: String },
}

#[derive(Subcommand, Debug)]
enum BindCmd {
    /// POST /native/software/bind (JSON file)
    Software { body: PathBuf },
    Workload { body: PathBuf },
    Intelligence { body: PathBuf },
}

#[derive(Subcommand, Debug)]
enum AppCmd {
    /// Scaffold Python-first (default) project with cnktr.yaml
    Init {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value = "python")]
        lang: String,
        #[arg(long, default_value = "my-app")]
        app_id: String,
    },
    /// Build signed AppPackageV2 `.cpkg` (+ `.package.pin.json`)
    Build {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "0.1.0")]
        version: String,
        /// Raw 32-byte or 64-hex Ed25519 seed file
        #[arg(long)]
        signing_key: Option<PathBuf>,
        #[arg(long, default_value = "local-dev")]
        key_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum PackageCmd {
    /// Check whether a pin would be admitted under a profile
    Check {
        #[arg(long, default_value = "production")]
        profile: String,
        #[arg(long)]
        package_digest: Option<String>,
        #[arg(long)]
        package_id: Option<String>,
        #[arg(long, default_value_t = true)]
        signed: bool,
        #[arg(long)]
        package_pin: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Snapshot ConnectorConfigEnvelope from process env (node/runtime planes)
    Snapshot,
}

fn client(cli: &Cli) -> Result<ConnectorClient, String> {
    let mut cfg = ClientConfig::default();
    if let Some(u) = &cli.endpoint {
        cfg.base_url = u.clone();
    }
    if let Some(k) = &cli.api_key {
        cfg.api_key = Some(k.clone());
    }
    ConnectorClient::new(cfg).map_err(|e| e.to_string())
}

fn print_out(_cli: &Cli, v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
}

fn read_json(path: &PathBuf) -> Result<Value, String> {
    let s = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

fn load_pin(path: &PathBuf) -> Result<PackagePin, String> {
    let v = read_json(path)?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cnktros: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match &cli.command {
        Commands::Status => {
            let c = client(&cli)?;
            let st = c.status().map_err(|e| e.to_string())?;
            print_out(&cli, &serde_json::to_value(st).unwrap_or(json!({})));
        }
        Commands::Channels { action } => {
            let c = client(&cli)?;
            match action.as_ref().unwrap_or(&ChannelsCmd::List) {
                ChannelsCmd::List => {
                    print_out(&cli, &c.list_channels().map_err(|e| e.to_string())?);
                }
            }
        }
        Commands::Surfaces { action } => {
            let c = client(&cli)?;
            match action.as_ref().unwrap_or(&SurfacesCmd::List) {
                SurfacesCmd::List => {
                    print_out(&cli, &c.list_surfaces().map_err(|e| e.to_string())?);
                }
                SurfacesCmd::Probe { id } => {
                    print_out(&cli, &c.probe_surface(id).map_err(|e| e.to_string())?);
                }
            }
        }
        Commands::Invoke {
            body,
            package_digest,
            package_id,
            package_kind,
            signed,
            package_pin,
            lab,
        } => {
            let mut cfg = ClientConfig::default();
            if let Some(u) = &cli.endpoint {
                cfg.base_url = u.clone();
            }
            if let Some(k) = &cli.api_key {
                cfg.api_key = Some(k.clone());
            }
            if *lab {
                cfg.runtime_profile = RuntimeProfile::Lab;
            }
            let c = ConnectorClient::new(cfg).map_err(|e| e.to_string())?;
            let payload = read_json(body)?;
            let pin = if let Some(p) = package_pin {
                Some(load_pin(p)?)
            } else {
                match (package_id, package_digest) {
                    (Some(id), Some(dig)) => {
                        Some(PackagePin::new(id, dig, package_kind).with_signature(*signed))
                    }
                    (None, None) if *lab => None,
                    _ if *lab => None,
                    _ => {
                        return Err(
                            "invoke requires --package-pin or --package-id/--package-digest outside --lab"
                                .into(),
                        );
                    }
                }
            };
            let out = c.invoke(payload, pin).map_err(|e| e.to_string())?;
            print_out(&cli, &out);
        }
        Commands::Receipts { action } => {
            let c = client(&cli)?;
            match action {
                ReceiptsCmd::Get { operation_id } => {
                    print_out(
                        &cli,
                        &c.get_receipt(operation_id).map_err(|e| e.to_string())?,
                    );
                }
            }
        }
        Commands::Bind { action } => {
            let c = client(&cli)?;
            match action {
                BindCmd::Software { body } => {
                    print_out(
                        &cli,
                        &c.bind_software(read_json(body)?).map_err(|e| e.to_string())?,
                    );
                }
                BindCmd::Workload { body } => {
                    print_out(
                        &cli,
                        &c.create_workload(read_json(body)?).map_err(|e| e.to_string())?,
                    );
                }
                BindCmd::Intelligence { body } => {
                    print_out(
                        &cli,
                        &c.create_intelligence(read_json(body)?)
                            .map_err(|e| e.to_string())?,
                    );
                }
            }
        }
        Commands::App { action } => match action {
            AppCmd::Init { path, lang, app_id } => {
                let lang = lang.to_ascii_lowercase();
                if !matches!(lang.as_str(), "python" | "typescript" | "rust") {
                    return Err("lang must be python|typescript|rust (default python)".into());
                }
                let readme = app_build::scaffold_project(path, app_id, &lang)?;
                print_out(
                    &cli,
                    &json!({
                        "ok": true,
                        "readme": readme,
                        "path": path,
                        "lang": lang,
                        "app_id": app_id,
                        "next": "cnktros app build --path <dir> [--signing-key <seed>]",
                        "primary_language": "python",
                    }),
                );
            }
            AppCmd::Build {
                path,
                output,
                version,
                signing_key,
                key_id,
            } => {
                let result = app_build::build_app_package(
                    path,
                    output.as_deref(),
                    version,
                    signing_key.as_deref(),
                    key_id,
                )?;
                print_out(
                    &cli,
                    &json!({
                        "ok": true,
                        "package": result.package_path,
                        "pin_file": result.pin_path,
                        "pin": result.pin,
                        "signed": result.signed,
                        "honesty": result.honesty,
                        "primary_language": "python",
                    }),
                );
            }
        },
        Commands::Package { action } => match action {
            PackageCmd::Check {
                profile,
                package_digest,
                package_id,
                signed,
                package_pin,
            } => {
                use connector_native_contract::{admit_package_for_effect, gate_allows};
                let profile = RuntimeProfile::parse(profile);
                let pin = if let Some(p) = package_pin {
                    Some(load_pin(p)?)
                } else {
                    match (package_id, package_digest) {
                        (Some(id), Some(d)) => {
                            Some(PackagePin::new(id, d, "app").with_signature(*signed))
                        }
                        _ => None,
                    }
                };
                let decision = admit_package_for_effect(profile, pin.as_ref(), true);
                print_out(
                    &cli,
                    &json!({
                        "allowed": gate_allows(&decision),
                        "decision": decision,
                    }),
                );
                if !gate_allows(&decision) {
                    return Err(decision.honesty);
                }
            }
        },
        Commands::Config { action } => match action {
            ConfigCmd::Snapshot => {
                use connector_native_contract::ConnectorConfigEnvelope;
                let env = ConnectorConfigEnvelope::from_process_env();
                print_out(&cli, &serde_json::to_value(env).unwrap_or(json!({})));
            }
        },
    }
    Ok(())
}
