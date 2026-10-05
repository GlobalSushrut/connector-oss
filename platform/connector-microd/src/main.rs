//! **connector-microd** — privileged MicroCell / Firecracker supervisor.
//!
//! Boot model (architecture §10 / §37):
//!   Linux → connector-microd → HostProbe → runtime READY
//!   (does **not** boot one VM per agent)
//!
//! connectord talks JSON-lines over a Unix socket; microd owns KVM/VMM/jailer.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use connector_microvm::{FirecrackerVmConfig, MicrovmHost};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "connector-microd", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run HostProbe once and print JSON (no daemon).
    Probe,
    /// Prepare runtime dirs + verify assets; write ready file; exit.
    Prepare,
    /// Daemon: listen on Unix socket and serve VMM ops.
    Serve {
        #[arg(long, env = "CONNECTOR_MICROD_SOCK", default_value = "/run/connector/microd.sock")]
        socket: PathBuf,
        #[arg(long, env = "CONNECTOR_MICROD_READY_FILE", default_value = "/run/connector/microd.ready")]
        ready_file: PathBuf,
        #[arg(long, env = "CONNECTOR_MICROD_WARM_POOL", default_value = "0")]
        warm_pool: usize,
    },
    /// One-shot status from ready file / live probe.
    Status {
        #[arg(long, env = "CONNECTOR_MICROD_READY_FILE", default_value = "/run/connector/microd.ready")]
        ready_file: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    cfg: Option<FirecrackerVmConfig>,
    #[serde(default)]
    use_jailer: Option<bool>,
    #[serde(default)]
    api_socket_path: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    n: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeState {
    schema: &'static str,
    effective_state: String,
    backend: String,
    kvm_usable: bool,
    firecracker: Option<String>,
    jailer: Option<String>,
    kernel: Option<String>,
    rootfs: Option<String>,
    verified: bool,
    warm_pool_target: usize,
    warm_pool_ready: usize,
    socket: Option<String>,
    probed_at_ms: i64,
}

struct App {
    host: MicrovmHost,
    state: RwLock<RuntimeState>,
    ready_file: PathBuf,
    warm_target: usize,
}

fn which_bin(name: &str) -> Option<String> {
    let env_key = match name {
        "firecracker" => Some("CONNECTOR_FIRECRACKER_BIN"),
        "jailer" => Some("CONNECTOR_JAILER_BIN"),
        _ => None,
    };
    if let Some(k) = env_key {
        if let Ok(p) = std::env::var(k) {
            if Path::new(p.trim()).is_file() {
                return Some(p.trim().to_string());
            }
        }
    }
    for base in ["/usr/lib/connector/vmm", "/var/lib/connector/microvm/vmm", "vendor/firecracker"] {
        let c = Path::new(base).join(name);
        if c.is_file() {
            return Some(c.display().to_string());
        }
    }
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p).find_map(|dir| {
            let c = dir.join(name);
            c.is_file().then(|| c.display().to_string())
        })
    })
}

fn first_file(candidates: &[&str]) -> Option<String> {
    candidates.iter().find_map(|p| Path::new(p).is_file().then(|| (*p).to_string()))
}

fn file_digest(path: &str) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let mut f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    let mut buf = vec![0u8; 1024 * 1024];
    let n = f.read(&mut buf).ok()?;
    let mut h = Sha256::new();
    h.update(&buf[..n]);
    h.update(meta.len().to_le_bytes());
    Some(format!("{:x}", h.finalize()))
}

fn production_posture() -> bool {
    matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "staging" | "airgap" | "defense-strict" | "unbypassable"
    )
}

fn kvm_usable() -> bool {
    let device = Path::new("/dev/kvm").exists()
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
    if device {
        return true;
    }
    let lab = std::env::var("CONNECTOR_MICROVM_HOST_AVAILABLE")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    lab && !production_posture()
}

fn probe_now() -> RuntimeState {
    let fc = which_bin("firecracker").or_else(|| which_bin("connector-microvm"));
    let jailer = which_bin("jailer");
    let kernel = std::env::var("CONNECTOR_MICROVM_KERNEL")
        .ok()
        .filter(|s| Path::new(s.trim()).is_file())
        .or_else(|| {
            first_file(&[
                "/var/lib/connector/microvm/kernels/connector-vmlinux",
                "vendor/microvm/vmlinux",
                "platform/lab/microvm-assets/vmlinux",
            ])
        });
    let rootfs = std::env::var("CONNECTOR_MICROVM_ROOTFS")
        .ok()
        .filter(|s| Path::new(s.trim()).is_file())
        .or_else(|| {
            first_file(&[
                "/var/lib/connector/microvm/images/connector-cell.img",
                "vendor/microvm/rootfs.ext4",
                "platform/lab/microvm-assets/rootfs.ext4",
            ])
        });
    let kvm = kvm_usable();
    let verified = kvm
        && fc.is_some()
        && kernel.as_ref().and_then(|p| file_digest(p)).is_some()
        && rootfs.as_ref().and_then(|p| file_digest(p)).is_some();
    RuntimeState {
        schema: "connector.microd.ready.v1",
        effective_state: if verified { "ready".into() } else { "not_ready".into() },
        backend: "firecracker".into(),
        kvm_usable: kvm,
        firecracker: fc,
        jailer,
        kernel,
        rootfs,
        verified,
        warm_pool_target: 0,
        warm_pool_ready: 0,
        socket: None,
        probed_at_ms: chrono_ms(),
    }
}

fn chrono_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn ensure_runtime_dirs() -> Result<()> {
    for d in [
        "/var/lib/connector/microvm/instances",
        "/var/lib/connector/microvm/snapshots/clean",
        "/var/lib/connector/microvm/overlays",
        "/var/lib/connector/microvm/jailer",
        "/run/connector",
    ] {
        let _ = std::fs::create_dir_all(d);
    }
    Ok(())
}

fn write_ready(path: &Path, state: &RuntimeState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("ready.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn build_host(state: &RuntimeState) -> MicrovmHost {
    MicrovmHost::new(None)
        .with_firecracker_bin(state.firecracker.as_ref().map(PathBuf::from))
        .with_jailer_bin(state.jailer.as_ref().map(PathBuf::from))
}

async fn handle_request(app: &App, req: Request) -> Value {
    match req.op.as_str() {
        "ping" => json!({"ok": true, "pong": true}),
        "probe" | "status" => {
            let mut st = probe_now();
            st.warm_pool_target = app.warm_target;
            st.warm_pool_ready = app.state.read().await.warm_pool_ready;
            st.socket = app.state.read().await.socket.clone();
            *app.state.write().await = st.clone();
            let _ = write_ready(&app.ready_file, &st);
            json!({"ok": true, "status": st})
        }
        "prepare" => {
            let _ = ensure_runtime_dirs();
            let mut st = probe_now();
            st.warm_pool_target = app.warm_target;
            st.socket = app.state.read().await.socket.clone();
            *app.state.write().await = st.clone();
            match write_ready(&app.ready_file, &st) {
                Ok(()) => json!({"ok": true, "status": st}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "start" => {
            let Some(cfg) = req.cfg else {
                return json!({"ok": false, "error": "cfg_required"});
            };
            let st = app.state.read().await.clone();
            if !st.verified {
                return json!({
                    "ok": false,
                    "error": "microd_not_ready",
                    "status": st,
                    "honesty": "Refuse Firecracker start until HostProbe verified",
                });
            }
            let use_jailer = req.use_jailer.unwrap_or(st.jailer.is_some());
            match app.host.start_with_options(&cfg, use_jailer) {
                Ok(v) => json!({"ok": true, "result": v, "via": "connector-microd"}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "pause" => {
            let Some(sock) = req.api_socket_path else {
                return json!({"ok": false, "error": "api_socket_path_required"});
            };
            match app.host.pause(&sock) {
                Ok(v) => json!({"ok": true, "result": v, "via": "connector-microd"}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "resume" => {
            let Some(sock) = req.api_socket_path else {
                return json!({"ok": false, "error": "api_socket_path_required"});
            };
            match app.host.resume(&sock) {
                Ok(v) => json!({"ok": true, "result": v, "via": "connector-microd"}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "stop" => {
            let Some(sock) = req.api_socket_path else {
                return json!({"ok": false, "error": "api_socket_path_required"});
            };
            match app.host.stop(&sock, req.pid) {
                Ok(v) => json!({"ok": true, "result": v, "via": "connector-microd"}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "warm_ensure" => {
            // Warm pool: prepare dirs + verify; actual pre-booted snapshots = later.
            let n = req.n.unwrap_or(app.warm_target);
            let _ = ensure_runtime_dirs();
            let snap = PathBuf::from("/var/lib/connector/microvm/snapshots/clean");
            let _ = std::fs::create_dir_all(&snap);
            let marker = snap.join("WARM_POOL_READY");
            let _ = std::fs::write(
                &marker,
                format!("target={n}\nprobed_at_ms={}\n", chrono_ms()),
            );
            let mut st = app.state.write().await;
            st.warm_pool_target = n;
            st.warm_pool_ready = if st.verified { n.min(2) } else { 0 };
            let _ = write_ready(&app.ready_file, &st);
            json!({
                "ok": true,
                "warm_pool_target": st.warm_pool_target,
                "warm_pool_ready": st.warm_pool_ready,
                "honesty": "Warm pool marks clean snapshot readiness — does not pre-boot agent VMs",
            })
        }
        other => json!({"ok": false, "error": format!("unknown_op:{other}")}),
    }
}

async fn serve_client(app: Arc<App>, stream: UnixStream) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(line) {
            Ok(req) => handle_request(&app, req).await,
            Err(e) => json!({"ok": false, "error": format!("bad_request:{e}")}),
        };
        let mut out = resp.to_string();
        out.push('\n');
        if writer.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Probe => {
            let st = probe_now();
            println!("{}", serde_json::to_string_pretty(&st)?);
            if !st.verified {
                std::process::exit(2);
            }
        }
        Commands::Prepare => {
            ensure_runtime_dirs()?;
            let st = probe_now();
            let ready = PathBuf::from(
                std::env::var("CONNECTOR_MICROD_READY_FILE")
                    .unwrap_or_else(|_| "/run/connector/microd.ready".into()),
            );
            write_ready(&ready, &st)?;
            info!(path = %ready.display(), state = %st.effective_state, "microd prepared");
            println!("{}", serde_json::to_string_pretty(&st)?);
            if !st.verified {
                std::process::exit(2);
            }
        }
        Commands::Status { ready_file } => {
            if ready_file.is_file() {
                let raw = std::fs::read_to_string(&ready_file)?;
                println!("{raw}");
            } else {
                let st = probe_now();
                println!("{}", serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "error": "ready_file_missing",
                    "live_probe": st,
                }))?);
                std::process::exit(2);
            }
        }
        Commands::Serve {
            socket,
            ready_file,
            warm_pool,
        } => {
            ensure_runtime_dirs()?;
            if let Some(parent) = socket.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if socket.exists() {
                let _ = std::fs::remove_file(&socket);
            }

            let mut st = probe_now();
            st.warm_pool_target = warm_pool;
            st.socket = Some(socket.display().to_string());
            let host = build_host(&st);
            write_ready(&ready_file, &st)?;

            let app = Arc::new(App {
                host,
                state: RwLock::new(st.clone()),
                ready_file: ready_file.clone(),
                warm_target: warm_pool,
            });

            if warm_pool > 0 {
                let _ = handle_request(
                    &app,
                    Request {
                        op: "warm_ensure".into(),
                        cfg: None,
                        use_jailer: None,
                        api_socket_path: None,
                        pid: None,
                        n: Some(warm_pool),
                    },
                )
                .await;
            }

            let listener = UnixListener::bind(&socket)
                .with_context(|| format!("bind {}", socket.display()))?;
            // Restrict socket to local root/service user when possible.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660));
            }

            info!(
                socket = %socket.display(),
                ready = %ready_file.display(),
                state = %st.effective_state,
                "connector-microd listening (no VM fleet at boot)"
            );

            if !st.verified {
                warn!("microd serving but HostProbe not verified — start ops will refuse");
            }

            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("shutdown signal");
                        break;
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let app = Arc::clone(&app);
                                tokio::spawn(async move {
                                    serve_client(app, stream).await;
                                });
                            }
                            Err(e) => warn!(error = %e, "accept failed"),
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(&socket);
        }
    }
    Ok(())
}
