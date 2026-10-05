//! **connector-kerneld** — default host reconciler for Connector kernel policy.
//!
//! Recommended **military / prod** default: enforce egress with **systemd**
//! [`IPAddressAllow=`](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html)
//! (and optionally `NFTSet=` for nft sets; see runbook). This binary reads platform truth and
//! materializes **unit drop-ins**.
//!
//! **eBPF path (Seven Pillars §2):** `ebpf-load` / `ebpf-status` / `ebpf-deny-mark` load a real
//! `cgroup/skb` mark-deny program via bpftool and pin under `/sys/fs/bpf/connector/`.
//! `ebpf_loaded` is true only when bpffs pins exist — never from an env flag alone.
//!
//! **T2 transparent egress:** `egress-redirect-load` (cgroup/connect4) + `nft-redirect-apply`.

mod ebpf_host;
mod egress_redirect;

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tokio::net::lookup_host;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "connector-kerneld", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Fetch `GET /api/v1/kernel/status` and print JSON `data` (health / debug).
    PrintSnapshot,
    /// Emit a systemd unit **drop-in** `[Service]` fragment with `IPAddressAllow=` from the active profile.
    RenderDropin {
        /// Connector agent PID (must match `POST .../kernel/agents/:pid/attach`).
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: String,
        /// Write fragment here (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Max resolved addresses per hostname (bounds drop-in size).
        #[arg(long, default_value = "8")]
        max_addrs_per_host: usize,
    },
    /// Periodically re-fetch; on change or every tick, re-write drop-in and optionally `systemctl try-reload-or-restart`.
    Watch {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: String,
        #[arg(long, default_value = "30", env = "CONNECTOR_KERNELD_INTERVAL_SEC")]
        interval_sec: u64,
        #[arg(long, env = "CONNECTOR_KERNELD_DROPIN_PATH")]
        output: PathBuf,
        /// If set, run `systemctl try-reload-or-restart <UNIT>` after each successful write.
        #[arg(long, env = "CONNECTOR_KERNELD_SYSTEMD_UNIT")]
        systemd_unit: Option<String>,
        #[arg(long, default_value = "8")]
        max_addrs_per_host: usize,
    },
    /// Load cgroup/skb mark-deny eBPF program and pin under /sys/fs/bpf/connector/<agent>.
    EbpfLoad {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: String,
        #[arg(long)]
        cgroup: Option<String>,
    },
    /// Probe bpffs pins — honest ebpf_loaded status.
    EbpfStatus {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: Option<String>,
    },
    /// Insert/remove a deny mark in the pinned deny_marks map.
    EbpfDenyMark {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: String,
        #[arg(long)]
        mark: u32,
        #[arg(long, default_value_t = true)]
        deny: bool,
    },
    /// Remove bpffs pins for an agent.
    EbpfUnload {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: String,
    },
    /// T2 — load cgroup/connect4 rewrite to Connector egress proxy.
    EgressRedirectLoad {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: String,
        #[arg(long)]
        cgroup: Option<String>,
    },
    /// T2 — status of connect4 redirect pins + proxy listen.
    EgressRedirectStatus {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: Option<String>,
    },
    /// T2 — apply nftables REDIRECT to egress proxy port (CAP_NET_ADMIN).
    NftRedirectApply {
        #[arg(long, env = "CONNECTOR_KERNELD_AGENT_PID")]
        agent: String,
    },
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope {
    ok: bool,
    data: Option<serde_json::Value>,
}

struct PlatformClient {
    base: String,
    api_key: String,
    http: reqwest::Client,
}

impl PlatformClient {
    fn from_env() -> Result<Self> {
        let base = std::env::var("CONNECTOR_PLATFORM_URL")
            .or_else(|_| std::env::var("CONNECTOR_TEST_URL"))
            .unwrap_or_else(|_| "http://127.0.0.1:9735".to_string());
        let base = base.trim_end_matches('/').to_string();
        let api_key = std::env::var("CONNECTOR_API_KEY")
            .or_else(|_| std::env::var("CONNECTOR_TEST_API_KEY"))
            .context("set CONNECTOR_API_KEY (or CONNECTOR_TEST_API_KEY) for platform auth")?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("reqwest client")?;
        Ok(Self {
            base,
            api_key,
            http,
        })
    }

    async fn get_kernel_status(&self) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/kernel/status", self.base);
        let resp = self
            .http
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_key.trim()),
            )
            .send()
            .await
            .with_context(|| format!("GET {}", url))?;
        let status = resp.status();
        if !status.is_success() {
            let t = resp.text().await.unwrap_or_default();
            anyhow::bail!("kernel/status HTTP {}: {}", status, t);
        }
        let env: ApiEnvelope = resp.json().await.context("parse kernel/status JSON")?;
        if !env.ok {
            anyhow::bail!("kernel/status ok=false");
        }
        env.data.ok_or_else(|| anyhow!("kernel/status missing data"))
    }

    /// ACK host apply after systemd drop-in write → platform HostApplyState::Active.
    async fn confirm_host_apply(&self, agent: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/kernel/agents/{}/confirm-host-apply",
            self.base, agent
        );
        let resp = self
            .http
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_key.trim()),
            )
            .json(&serde_json::json!({
                "apply_backend": "systemd_dropin",
            }))
            .send()
            .await
            .with_context(|| format!("POST {}", url))?;
        let status = resp.status();
        if !status.is_success() {
            let t = resp.text().await.unwrap_or_default();
            anyhow::bail!("confirm-host-apply HTTP {}: {}", status, t);
        }
        Ok(())
    }

    async fn confirm_host_apply_bpf(
        &self,
        agent: &str,
        pin_prefix: std::path::PathBuf,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/kernel/agents/{}/confirm-host-apply",
            self.base, agent
        );
        let resp = self
            .http
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_key.trim()),
            )
            .json(&serde_json::json!({
                "apply_backend": "bpf",
                "bpf_pin_prefix": pin_prefix.display().to_string(),
                "ebpf_probe_ok": true,
            }))
            .send()
            .await
            .with_context(|| format!("POST {}", url))?;
        let status = resp.status();
        if !status.is_success() {
            let t = resp.text().await.unwrap_or_default();
            anyhow::bail!("confirm-host-apply bpf HTTP {}: {}", status, t);
        }
        Ok(())
    }
}

fn find_agent_row(snapshot: &serde_json::Value, agent_pid: &str) -> Result<serde_json::Value> {
    let agents = snapshot
        .get("agents")
        .and_then(|a| a.as_array())
        .context("snapshot.agents missing")?;
    for row in agents {
        if row.get("agent_pid").and_then(|v| v.as_str()) == Some(agent_pid) {
            return Ok(row.clone());
        }
    }
    anyhow::bail!("no agent {:?} in kernel snapshot (attach first)", agent_pid)
}

fn profile_for_attachment(
    snapshot: &serde_json::Value,
    attachment: &serde_json::Value,
) -> Result<serde_json::Value> {
    let pid = attachment
        .get("profile_id")
        .and_then(|v| v.as_str())
        .context("attachment.profile_id")?;
    let profiles = snapshot
        .get("profiles")
        .and_then(|p| p.as_array())
        .context("snapshot.profiles missing")?;
    for p in profiles {
        if p.get("profile_id").and_then(|v| v.as_str()) == Some(pid) {
            return Ok(p.clone());
        }
    }
    anyhow::bail!("profile {:?} not found in snapshot", pid)
}

async fn resolve_allowlist_ips(
    hostnames: &[String],
    max_per_host: usize,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for h in hostnames {
        let host = h.trim();
        if host.is_empty() {
            continue;
        }
        let mut n = 0usize;
        let sock = (host, 443u16);
        let iter = lookup_host(sock)
            .await
            .with_context(|| format!("DNS lookup_host {}", host))?;
        for sa in iter {
            let ip = sa.ip();
            let s = ip.to_string();
            if seen.insert(s.clone()) {
                out.push(s);
                n += 1;
                if n >= max_per_host {
                    break;
                }
            }
        }
    }
    Ok(out)
}

fn license_enforcement_enabled() -> bool {
    matches!(
        std::env::var("CONNECTOR_LICENSE_ENFORCE")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

fn license_time_valid(snapshot: &serde_json::Value) -> bool {
    snapshot
        .get("license")
        .and_then(|l| l.get("time_valid"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

fn license_materialization_revision(snapshot: &serde_json::Value) -> u64 {
    snapshot
        .get("license")
        .and_then(|l| l.get("materialization_revision"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// When license enforcement is on and the platform reports `time_valid: false`, block all IP egress
/// via systemd `IPAddressDeny=any` (see systemd.resource-control(5)).
fn render_license_deny_fragment(agent_pid: &str, combined_revision: u64) -> String {
    let mut s = String::new();
    s.push_str("# Generated by connector-kerneld — LICENSE DENY (all egress blocked).\n");
    s.push_str("# Platform GET /api/v1/kernel/status included license.time_valid=false.\n");
    s.push_str("# Renew license on the platform host; clear CONNECTOR_LICENSE_ENFORCE only as break-glass.\n");
    s.push_str(&format!(
        "# agent_pid={} combined_revision={}\n",
        agent_pid, combined_revision
    ));
    s.push_str("[Service]\n");
    s.push_str("IPAddressDeny=any\n");
    s
}

fn render_flow_lease_deny_fragment(agent_pid: &str, combined_revision: u64) -> String {
    let mut s = String::new();
    s.push_str("# Generated by connector-kerneld — FLOW LEASE DENY (no active egress tickets).\n");
    s.push_str("# Platform snapshot flow_lease.enforcement_enabled=true and active_leases=0.\n");
    s.push_str("# Admit a governed flow on the platform to mint a lease; or disable enforcement.\n");
    s.push_str(&format!(
        "# agent_pid={} combined_revision={}\n",
        agent_pid, combined_revision
    ));
    s.push_str("[Service]\n");
    s.push_str("IPAddressDeny=any\n");
    s
}

fn flow_lease_enforcement_blocks(snapshot: &serde_json::Value) -> bool {
    let Some(fl) = snapshot.get("flow_lease") else {
        return false;
    };
    let enforcement = fl
        .get("enforcement_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !enforcement {
        return false;
    }
    fl.get("active_leases")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        == 0
}

/// Hostnames kerneld should allow when lease enforcement is on.
///
/// Prefer platform-computed `kernel_cage_hostnames`. When constrained leases
/// exist, narrow the cage to those hosts instead of the full profile allowlist.
fn flow_lease_cage_hostnames(
    snapshot: &serde_json::Value,
    profile_hosts: &[String],
) -> Vec<String> {
    let Some(fl) = snapshot.get("flow_lease") else {
        return profile_hosts.to_vec();
    };
    let enforce = fl
        .get("enforcement_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !enforce {
        return profile_hosts.to_vec();
    }
    if let Some(pre) = fl.get("kernel_cage_hostnames").and_then(|v| v.as_array()) {
        let hosts: Vec<String> = pre
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect();
        if !hosts.is_empty() {
            return hosts;
        }
    }
    let mut derived = std::collections::BTreeSet::new();
    if let Some(leases) = fl.get("leases").and_then(|v| v.as_array()) {
        for l in leases {
            let constrained = l.get("destination_host").is_some()
                || l.get("destination_ip_cidr").is_some()
                || l.get("destination_port").is_some()
                || l.get("destination_protocol").is_some();
            if !constrained {
                continue;
            }
            if let Some(h) = l.get("destination_host").and_then(|v| v.as_str()) {
                let h = h.trim();
                if !h.is_empty() {
                    derived.insert(h.to_string());
                }
            }
        }
    }
    if derived.is_empty() {
        profile_hosts.to_vec()
    } else {
        derived.into_iter().collect()
    }
}

/// Desired-vs-applied honesty for Seven Pillars §2/§4 (no eBPF claim).
fn desired_vs_applied_report(
    snapshot: &serde_json::Value,
    applied_fragment: &str,
) -> serde_json::Value {
    let fl = snapshot.get("flow_lease").cloned().unwrap_or(serde_json::json!({}));
    let desired_deny = flow_lease_enforcement_blocks(snapshot);
    let applied_deny = applied_fragment.contains("IPAddressDeny=any");
    let desired_allows: Vec<String> = fl
        .get("leases")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|l| l.get("lease_id").and_then(|x| x.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let drift = desired_deny != applied_deny;
    let fingerprint = format!(
        "{:x}-{}",
        applied_fragment.len(),
        &applied_fragment
            .bytes()
            .fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64))
            .to_string()
    );
    let ebpf_loaded = ebpf_host::probe_loaded(None);
    serde_json::json!({
        "schema": "connector.kerneld.desired_vs_applied.v1",
        "mechanism": if ebpf_loaded {
            "systemd_ipaddress_allow_deny+ebpf_cgroup_skb_mark_deny"
        } else {
            "systemd_ipaddress_allow_deny"
        },
        "ebpf_loaded": ebpf_loaded,
        "ebpf": ebpf_host::status_json(None),
        "honesty": if ebpf_loaded {
            "eBPF pins present under /sys/fs/bpf/connector — real loaded program"
        } else {
            "systemd drop-ins active; eBPF not loaded — run connector-kerneld ebpf-load"
        },
        "desired": {
            "flow_lease_deny_all": desired_deny,
            "active_lease_ids": desired_allows,
        },
        "applied": {
            "ip_address_deny_any": applied_deny,
            "fragment_fingerprint": fingerprint,
        },
        "drift": drift,
        "drift_is_production_fault": drift,
    })
}

fn render_ip_address_allow_fragment(
    agent_pid: &str,
    policy_revision: u64,
    profile_id: &str,
    ips: &[String],
) -> String {
    let mut s = String::new();
    s.push_str("# Generated by connector-kerneld — Connector platform kernel policy.\n");
    s.push_str("# Default prod path: systemd egress allowlist (systemd.resource-control(5)).\n");
    s.push_str(&format!(
        "# agent_pid={} profile_id={} policy_revision={}\n",
        agent_pid, profile_id, policy_revision
    ));
    s.push_str("[Service]\n");
    for ip in ips {
        if ip.contains(':') {
            s.push_str(&format!("IPAddressAllow={}/128\n", ip));
        } else {
            s.push_str(&format!("IPAddressAllow={}/32\n", ip));
        }
    }
    if ips.is_empty() {
        s.push_str("# No resolved IPs — verify allow_hostnames / DNS from the worker host.\n");
    }
    s
}

/// One `GET /api/v1/kernel/status` → drop-in body + policy revision from attachment.
async fn materialize_dropin(
    snapshot: &serde_json::Value,
    agent: &str,
    max_addrs_per_host: usize,
) -> Result<(String, u64)> {
    let row = find_agent_row(snapshot, agent)?;
    let att = row
        .get("attachment")
        .context("agent row missing attachment")?;
    let state = att
        .get("host_apply_state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    if state != "active" {
        warn!(
            agent = %agent,
            host_apply_state = %state,
            "attachment not active; drop-in still generated from profile if present"
        );
    }
    let profile = profile_for_attachment(snapshot, att)?;
    let profile_allow: Vec<String> = profile
        .get("allow_hostnames")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let allow = flow_lease_cage_hostnames(snapshot, &profile_allow);
    let policy_revision = att
        .get("policy_revision")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let profile_id = profile
        .get("profile_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let ips = resolve_allowlist_ips(&allow, max_addrs_per_host).await?;
    let mut body = render_ip_address_allow_fragment(
        agent,
        policy_revision,
        profile_id,
        &ips,
    );
    let lic_rev = license_materialization_revision(snapshot);
    let combined_rev = policy_revision.wrapping_add(lic_rev);
    if license_enforcement_enabled() && !license_time_valid(snapshot) {
        body = render_license_deny_fragment(agent, combined_rev);
        return Ok((body, combined_rev));
    }
    if flow_lease_enforcement_blocks(snapshot) {
        body = render_flow_lease_deny_fragment(agent, combined_rev);
        return Ok((body, combined_rev));
    }
    // Constrained leases with empty DNS resolution → fail closed.
    let enforce = snapshot
        .get("flow_lease")
        .and_then(|fl| fl.get("enforcement_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let constrained = snapshot
        .get("flow_lease")
        .and_then(|fl| fl.get("constrained_leases"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if enforce && constrained > 0 && ips.is_empty() && !allow.is_empty() {
        body = render_flow_lease_deny_fragment(agent, combined_rev);
        return Ok((body, combined_rev));
    }
    Ok((body, combined_rev))
}

fn write_fragment(path: &Option<PathBuf>, body: &str) -> Result<()> {
    if let Some(p) = path {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("mkdir {:?}", parent))?;
        }
        let mut f = std::fs::File::create(p).with_context(|| format!("create {:?}", p))?;
        f.write_all(body.as_bytes())?;
        info!(path = %p.display(), bytes = body.len(), "wrote drop-in fragment");
    } else {
        std::io::stdout().write_all(body.as_bytes())?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // eBPF local commands do not require platform auth.
    let needs_platform = !matches!(
        cli.command,
        Commands::EbpfStatus { .. }
            | Commands::EbpfLoad { .. }
            | Commands::EbpfDenyMark { .. }
            | Commands::EbpfUnload { .. }
            | Commands::EgressRedirectLoad { .. }
            | Commands::EgressRedirectStatus { .. }
            | Commands::NftRedirectApply { .. }
    );

    match &cli.command {
        Commands::EbpfLoad { agent, cgroup } => {
            let v = ebpf_host::load_and_pin(agent, cgroup.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            if v.get("ebpf_loaded").and_then(|x| x.as_bool()) == Some(true) {
                if let Ok(client) = PlatformClient::from_env() {
                    if let Err(e) = client
                        .confirm_host_apply_bpf(agent, ebpf_host::agent_pin_dir(agent))
                        .await
                    {
                        warn!(%agent, "confirm-host-apply bpf: {:#}", e);
                    } else {
                        info!(%agent, "host apply confirmed Active (bpf)");
                    }
                } else {
                    info!("skip platform confirm (no CONNECTOR_API_KEY) — pins loaded locally");
                }
            }
            return Ok(());
        }
        Commands::EbpfStatus { agent } => {
            let v = ebpf_host::status_json(agent.as_deref());
            println!("{}", serde_json::to_string_pretty(&v)?);
            if ebpf_host::require_ebpf() && !ebpf_host::probe_loaded(agent.as_deref()) {
                return Err(anyhow!(
                    "CONNECTOR_EBPF_REQUIRE=1 but eBPF pins not present"
                ));
            }
            return Ok(());
        }
        Commands::EbpfDenyMark { agent, mark, deny } => {
            let v = ebpf_host::deny_mark(agent, *mark, *deny)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        Commands::EbpfUnload { agent } => {
            let v = ebpf_host::unload(agent)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        Commands::EgressRedirectLoad { agent, cgroup } => {
            let v = egress_redirect::load_connect_redirect(agent, cgroup.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            if egress_redirect::require_kernel_redirect()
                && !egress_redirect::probe_redirect_loaded(agent)
            {
                return Err(anyhow!(
                    "CONNECTOR_TRANSPARENT_EGRESS_KERNEL=1 but connect4 pins missing"
                ));
            }
            return Ok(());
        }
        Commands::EgressRedirectStatus { agent } => {
            let v = egress_redirect::status_json(agent.as_deref());
            println!("{}", serde_json::to_string_pretty(&v)?);
            if egress_redirect::require_kernel_redirect() {
                if let Some(a) = agent {
                    if !egress_redirect::probe_redirect_loaded(a) {
                        return Err(anyhow!(
                            "CONNECTOR_TRANSPARENT_EGRESS_KERNEL=1 but redirect not loaded"
                        ));
                    }
                }
            }
            return Ok(());
        }
        Commands::NftRedirectApply { agent } => {
            let v = egress_redirect::apply_nft_redirect(agent)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        _ => {}
    }

    let _ = needs_platform;
    let client = PlatformClient::from_env()?;

    match cli.command {
        Commands::PrintSnapshot => {
            let v = client.get_kernel_status().await?;
            // Include desired-vs-applied report for the empty/deny case without writing.
            let agent = std::env::var("CONNECTOR_KERNELD_AGENT_PID")
                .unwrap_or_else(|_| "snapshot".into());
            let (body, _) = materialize_dropin(&v, &agent, 8).await.unwrap_or_else(|_| {
                (
                    "# unavailable\n[Service]\nIPAddressDeny=any\n".into(),
                    0,
                )
            });
            let report = desired_vs_applied_report(&v, &body);
            let ebpf = ebpf_host::status_json(Some(agent.as_str()));
            let mut out = v;
            if let Some(obj) = out.as_object_mut() {
                obj.insert("desired_vs_applied".into(), report);
                obj.insert("ebpf".into(), ebpf);
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Commands::RenderDropin {
            agent,
            output,
            max_addrs_per_host,
        } => {
            let snap = client.get_kernel_status().await?;
            let (body, rev) = materialize_dropin(&snap, &agent, max_addrs_per_host).await?;
            info!(policy_revision = rev, "rendered drop-in");
            write_fragment(&output, &body)?;
            if output.is_some() {
                if let Err(e) = client.confirm_host_apply(&agent).await {
                    warn!(%agent, "confirm-host-apply after render: {:#}", e);
                } else {
                    info!(%agent, "host apply confirmed Active after render-dropin");
                }
            }
        }
        Commands::Watch {
            agent,
            interval_sec,
            output,
            systemd_unit,
            max_addrs_per_host,
        } => {
            let mut tick = interval(Duration::from_secs(interval_sec));
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut last_rev: Option<u64> = None;
            loop {
                tick.tick().await;
                match client.get_kernel_status().await {
                    Ok(snap) => match materialize_dropin(&snap, &agent, max_addrs_per_host).await {
                        Ok((body, rev)) => {
                            if let Err(e) = write_fragment(&Some(output.clone()), &body) {
                                warn!("write drop-in: {:#}", e);
                                continue;
                            }
                            let rev_changed = last_rev != Some(rev);
                            if rev_changed {
                                info!(policy_revision = rev, "policy revision applied");
                                last_rev = Some(rev);
                            }
                            let mut confirm = rev_changed;
                            if let Some(ref unit) = systemd_unit {
                                let st = tokio::process::Command::new("systemctl")
                                    .args(["try-reload-or-restart", unit])
                                    .status()
                                    .await;
                                match st {
                                    Ok(s) if s.success() => {
                                        info!(%unit, "systemctl try-reload-or-restart ok");
                                        confirm = true;
                                    }
                                    Ok(s) => {
                                        warn!(%unit, code = ?s.code(), "systemctl returned non-zero");
                                        confirm = false;
                                    }
                                    Err(e) => {
                                        warn!(%unit, "systemctl failed: {}", e);
                                        confirm = false;
                                    }
                                }
                            }
                            if confirm {
                                // Promote Simulated → Active after host materialization.
                                if let Err(e) = client.confirm_host_apply(&agent).await {
                                    warn!(%agent, "confirm-host-apply failed: {:#}", e);
                                } else {
                                    info!(%agent, "host apply confirmed Active (systemd_dropin)");
                                }
                            }
                        }
                        Err(e) => warn!("materialize drop-in: {:#}", e),
                    },
                    Err(e) => warn!("kernel/status: {:#}", e),
                }
            }
        }
        // eBPF arms handled above (early return).
        Commands::EbpfLoad { .. }
        | Commands::EbpfStatus { .. }
        | Commands::EbpfDenyMark { .. }
        | Commands::EbpfUnload { .. }
        | Commands::EgressRedirectLoad { .. }
        | Commands::EgressRedirectStatus { .. }
        | Commands::NftRedirectApply { .. } => unreachable!("handled before platform client"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_lease_blocks_when_enforced_and_empty() {
        let snap = serde_json::json!({
            "flow_lease": {
                "enforcement_enabled": true,
                "active_leases": 0
            }
        });
        assert!(flow_lease_enforcement_blocks(&snap));
    }

    #[test]
    fn flow_lease_allows_when_leases_present() {
        let snap = serde_json::json!({
            "flow_lease": {
                "enforcement_enabled": true,
                "active_leases": 2
            }
        });
        assert!(!flow_lease_enforcement_blocks(&snap));
    }

    #[test]
    fn flow_lease_ignores_when_enforcement_off() {
        let snap = serde_json::json!({
            "flow_lease": {
                "enforcement_enabled": false,
                "active_leases": 0
            }
        });
        assert!(!flow_lease_enforcement_blocks(&snap));
    }

    #[test]
    fn flow_lease_deny_fragment_has_ip_deny() {
        let body = render_flow_lease_deny_fragment("agent-1", 42);
        assert!(body.contains("IPAddressDeny=any"));
        assert!(body.contains("FLOW LEASE DENY"));
    }

    #[test]
    fn cage_narrows_to_constrained_hosts() {
        let snap = serde_json::json!({
            "flow_lease": {
                "enforcement_enabled": true,
                "active_leases": 1,
                "constrained_leases": 1,
                "kernel_cage_hostnames": ["api.example.com"]
            }
        });
        let profile = vec!["api.example.com".into(), "cdn.example.com".into()];
        let allow = flow_lease_cage_hostnames(&snap, &profile);
        assert_eq!(allow, vec!["api.example.com".to_string()]);
    }

    #[test]
    fn cage_keeps_profile_when_unconstrained_only() {
        let snap = serde_json::json!({
            "flow_lease": {
                "enforcement_enabled": true,
                "active_leases": 1,
                "constrained_leases": 0,
                "kernel_cage_hostnames": []
            }
        });
        let profile = vec!["cdn.example.com".into()];
        let allow = flow_lease_cage_hostnames(&snap, &profile);
        assert_eq!(allow, profile);
    }
}
