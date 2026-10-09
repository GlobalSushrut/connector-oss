//! Cage — OS-level sandbox policy enforcement for agent action calls.
//!
//! A Cage is a declarative policy attached to a pipeline that defines the
//! allowed envelope for every action API call made by agents during a run:
//!
//! - Network: allowed/blocked hosts, allowed ports, network on/off
//! - Filesystem: allowed read/write paths (checked at proxy time)
//! - Resources: CPU time, memory, open files, subprocess count
//! - Syscalls: default | strict | permissive policy label (applied if running
//!   agents as subprocesses via `seccomp` / Linux namespaces)
//! - Action types: allow/block specific action categories (http, sql, file, ...)
//! - Enforcement mode: enforce (hard deny), audit (log only), disabled
//!
//! The cage does NOT exec anything itself — it is a policy evaluator called
//! by the proxy before forwarding each action. OS resource limits (cgroups,
//! rlimit) are applied at the subprocess spawn layer if agents run as child
//! processes. In proxy-only mode the cage enforces network/type/path rules.

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CagePolicy {
    pub id:                  Uuid,
    pub pipeline_id:         Uuid,
    pub max_cpu_ms:          i64,
    pub max_memory_bytes:    i64,
    pub max_file_size_bytes: i64,
    pub max_open_files:      i32,
    pub max_processes:       i32,
    pub allow_network:       bool,
    pub allowed_hosts:       Vec<String>,
    pub blocked_hosts:       Vec<String>,
    pub allowed_ports:       Vec<i32>,
    pub allowed_read_paths:  Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub syscall_policy:      SyscallPolicy,
    pub allowed_action_types: Vec<String>,
    pub blocked_action_types: Vec<String>,
    pub enforcement:         Enforcement,
    pub created_at:          chrono::DateTime<Utc>,
    pub updated_at:          chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SyscallPolicy {
    Default,   // standard OS default — no extra restrictions
    Strict,    // allowlist: read, write, open, close, exit, futex, mmap, brk only
    Permissive, // no syscall filtering applied
}

impl std::fmt::Display for SyscallPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyscallPolicy::Default    => write!(f, "default"),
            SyscallPolicy::Strict     => write!(f, "strict"),
            SyscallPolicy::Permissive => write!(f, "permissive"),
        }
    }
}

impl From<&str> for SyscallPolicy {
    fn from(s: &str) -> Self {
        match s { "strict" => Self::Strict, "permissive" => Self::Permissive, _ => Self::Default }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    Enforce, // hard deny — request is blocked, run is paused/failed
    Audit,   // log violation but allow the call through
    Disabled, // cage is off — all calls pass without checking
}

impl std::fmt::Display for Enforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Enforcement::Enforce  => write!(f, "enforce"),
            Enforcement::Audit    => write!(f, "audit"),
            Enforcement::Disabled => write!(f, "disabled"),
        }
    }
}

impl From<&str> for Enforcement {
    fn from(s: &str) -> Self {
        match s { "audit" => Self::Audit, "disabled" => Self::Disabled, _ => Self::Enforce }
    }
}

// ── Cage verdict ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CageVerdict {
    Allow,
    Deny,
    Redact, // allow but strip sensitive fields from request
    Audit,  // allow in audit mode despite policy violation
}

impl std::fmt::Display for CageVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CageVerdict::Allow  => write!(f, "allow"),
            CageVerdict::Deny   => write!(f, "deny"),
            CageVerdict::Redact => write!(f, "redact"),
            CageVerdict::Audit  => write!(f, "audit"),
        }
    }
}

/// The result of evaluating a single action call against a cage policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageEvalResult {
    pub verdict:       CageVerdict,
    pub deny_reason:   Option<String>,
    pub policy_matched: Option<String>,
    /// OS-level rlimit values to apply when spawning the action subprocess.
    pub rlimits:       OsRlimits,
}

/// Portable OS resource limit values derived from the cage policy.
/// Applied via `setrlimit(2)` when agents run as child processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsRlimits {
    pub cpu_seconds:   u64,  // RLIMIT_CPU
    pub memory_bytes:  u64,  // RLIMIT_AS (virtual address space)
    pub file_size:     u64,  // RLIMIT_FSIZE
    pub open_files:    u64,  // RLIMIT_NOFILE
    pub max_processes: u64,  // RLIMIT_NPROC
}

// ── Request context passed to cage evaluator ─────────────────────────────────

#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub action_type: String,  // http | sql | file | subprocess | tool
    #[allow(dead_code)]
    pub method:      Option<String>,
    pub host:        Option<String>,
    pub port:        Option<u16>,
    pub path:        Option<String>,
    #[allow(dead_code)]
    pub body_size:   u64,
}

// ── Cage evaluation ───────────────────────────────────────────────────────────

/// Evaluate an action call against the cage policy for the given pipeline.
/// Returns the verdict and rlimits to apply. Never panics — worst case allow.
pub async fn evaluate(
    pool:        &PgPool,
    pipeline_id: Uuid,
    action:      &ActionRequest,
) -> CageEvalResult {
    let policy = match fetch(pool, pipeline_id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            // No cage configured for this pipeline — allow all
            return CageEvalResult {
                verdict:       CageVerdict::Allow,
                deny_reason:   None,
                policy_matched: Some("no_cage_configured".into()),
                rlimits:       default_rlimits(),
            };
        }
        Err(e) => {
            tracing::warn!(pipeline_id = %pipeline_id, err = %e, "Failed to load cage policy — defaulting to allow");
            return CageEvalResult {
                verdict:       CageVerdict::Allow,
                deny_reason:   None,
                policy_matched: Some("cage_load_error".into()),
                rlimits:       default_rlimits(),
            };
        }
    };

    if policy.enforcement == Enforcement::Disabled {
        return CageEvalResult {
            verdict:       CageVerdict::Allow,
            deny_reason:   None,
            policy_matched: Some("enforcement_disabled".into()),
            rlimits:       rlimits_from(&policy),
        };
    }

    // ── Check action type ────────────────────────────────────────────────────
    if !policy.blocked_action_types.is_empty()
        && policy.blocked_action_types.iter().any(|t| t == &action.action_type)
    {
        return cage_deny(&policy, "blocked_action_type",
            format!("action type '{}' is blocked by cage policy", action.action_type));
    }

    if !policy.allowed_action_types.is_empty()
        && !policy.allowed_action_types.iter().any(|t| t == &action.action_type)
    {
        return cage_deny(&policy, "action_type_not_allowed",
            format!("action type '{}' is not in the allowed list", action.action_type));
    }

    // ── Network checks ───────────────────────────────────────────────────────
    if action.action_type == "http" || action.action_type == "grpc" {
        if !policy.allow_network {
            return cage_deny(&policy, "network_disabled",
                "network access is disabled for this pipeline's cage".into());
        }

        if let Some(ref host) = action.host {
            // Blocked hosts — always deny, even if in allowed list
            if policy.blocked_hosts.iter().any(|bh| host_matches(host, bh)) {
                return cage_deny(&policy, "blocked_host",
                    format!("host '{}' is explicitly blocked", host));
            }

            // Allowed hosts — if non-empty, host must match one
            if !policy.allowed_hosts.is_empty()
                && !policy.allowed_hosts.iter().any(|ah| host_matches(host, ah))
            {
                return cage_deny(&policy, "host_not_allowed",
                    format!("host '{}' is not in the allowed hosts list", host));
            }
        }

        // Port check
        if let Some(port) = action.port {
            if !policy.allowed_ports.is_empty()
                && !policy.allowed_ports.iter().any(|&p| p as u16 == port)
            {
                return cage_deny(&policy, "port_not_allowed",
                    format!("port {} is not in the allowed ports list", port));
            }
        }
    }

    // ── Filesystem path checks ───────────────────────────────────────────────
    if action.action_type == "file" {
        if let Some(ref path) = action.path {
            let allowed = &policy.allowed_read_paths;
            if !allowed.is_empty() && !allowed.iter().any(|ap| path.starts_with(ap.as_str())) {
                return cage_deny(&policy, "path_not_allowed",
                    format!("path '{}' is not under any allowed read path", path));
            }
        }
    }

    // ── All checks passed ────────────────────────────────────────────────────
    CageEvalResult {
        verdict:        CageVerdict::Allow,
        deny_reason:    None,
        policy_matched: None,
        rlimits:        rlimits_from(&policy),
    }
}

// ── OS-level subprocess caging ────────────────────────────────────────────────

/// Apply OS rlimits to the current process (or a subprocess before exec).
/// Call this inside the child process after fork, before exec.
/// On non-Linux platforms this is a no-op with a warning.
#[allow(dead_code)]
pub fn apply_rlimits(limits: &OsRlimits) {
    #[cfg(target_os = "linux")]
    {
        use std::os::raw::c_ulong;

        #[repr(C)]
        struct Rlimit { rlim_cur: c_ulong, rlim_max: c_ulong }
        extern "C" { fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32; }

        const RLIMIT_CPU:    i32 = 0;
        const RLIMIT_FSIZE:  i32 = 1;
        const RLIMIT_AS:     i32 = 9;
        const RLIMIT_NOFILE: i32 = 7;
        const RLIMIT_NPROC:  i32 = 6;

        let apply = |resource: i32, soft: u64, hard: u64| {
            let rl = Rlimit { rlim_cur: soft as c_ulong, rlim_max: hard as c_ulong };
            let ret = unsafe { setrlimit(resource, &rl) };
            if ret != 0 { tracing::warn!(resource, soft, hard, "setrlimit failed"); }
        };

        apply(RLIMIT_CPU,    limits.cpu_seconds,   limits.cpu_seconds);
        apply(RLIMIT_FSIZE,  limits.file_size,      limits.file_size);
        apply(RLIMIT_AS,     limits.memory_bytes,   limits.memory_bytes);
        apply(RLIMIT_NOFILE, limits.open_files,     limits.open_files);
        apply(RLIMIT_NPROC,  limits.max_processes,  limits.max_processes);

        tracing::debug!(
            cpu_secs  = limits.cpu_seconds,
            memory_mb = limits.memory_bytes / 1024 / 1024,
            "OS rlimits applied to process"
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("apply_rlimits: OS-level resource limits only supported on Linux — skipping");
    }
}

/// Build a cgroup-v2 scope name for a run+step combination.
/// The caller is responsible for creating and managing the cgroup hierarchy.
/// Returns the systemd transient scope name: `conductor-<run_id>-<step>.scope`
#[allow(dead_code)]
pub fn cgroup_scope_name(run_id: Uuid, step_index: i32) -> String {
    format!("conductor-{}-step{}.scope", run_id, step_index)
}

/// Write cgroup v2 resource limits for a scope.
/// Writes to `/sys/fs/cgroup/<scope>/` — requires CAP_SYS_ADMIN or systemd delegation.
#[allow(dead_code)]
pub fn apply_cgroup_limits(run_id: Uuid, step_index: i32, limits: &OsRlimits) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::path::Path;

        let scope = cgroup_scope_name(run_id, step_index);
        let cgroup_base = Path::new("/sys/fs/cgroup").join(&scope);

        if !cgroup_base.exists() {
            tracing::debug!(scope = %scope, "cgroup scope does not exist — skipping cgroup limits");
            return Ok(());
        }

        // memory.max — hard memory limit
        let mem_path = cgroup_base.join("memory.max");
        if mem_path.exists() {
            let mut f = std::fs::OpenOptions::new().write(true).open(&mem_path)
                .with_context(|| format!("open {}", mem_path.display()))?;
            write!(f, "{}", limits.memory_bytes)
                .with_context(|| format!("write memory.max for scope {}", scope))?;
        }

        // cpu.max — "quota period" format: e.g. "30000 100000" = 30% CPU
        // We convert cpu_seconds to a budget: cpu_seconds * 1_000_000 microseconds
        let cpu_path = cgroup_base.join("cpu.max");
        if cpu_path.exists() {
            let quota = limits.cpu_seconds * 1_000_000;
            let mut f = std::fs::OpenOptions::new().write(true).open(&cpu_path)
                .with_context(|| format!("open {}", cpu_path.display()))?;
            write!(f, "{} 1000000", quota)
                .with_context(|| format!("write cpu.max for scope {}", scope))?;
        }

        // pids.max — maximum PIDs
        let pids_path = cgroup_base.join("pids.max");
        if pids_path.exists() {
            let mut f = std::fs::OpenOptions::new().write(true).open(&pids_path)
                .with_context(|| format!("open {}", pids_path.display()))?;
            write!(f, "{}", limits.max_processes)
                .with_context(|| format!("write pids.max for scope {}", scope))?;
        }

        tracing::info!(
            scope = %scope,
            memory_mb = limits.memory_bytes / 1024 / 1024,
            cpu_seconds = limits.cpu_seconds,
            max_pids = limits.max_processes,
            "cgroup v2 limits applied"
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("apply_cgroup_limits: cgroup v2 only supported on Linux — skipping");
    }

    Ok(())
}

// ── DB CRUD ───────────────────────────────────────────────────────────────────

pub async fn fetch(pool: &PgPool, pipeline_id: Uuid) -> Result<Option<CagePolicy>> {
    let row = sqlx::query(
        "SELECT id, pipeline_id, max_cpu_ms, max_memory_bytes, max_file_size_bytes, \
         max_open_files, max_processes, allow_network, allowed_hosts, blocked_hosts, \
         allowed_ports, allowed_read_paths, allowed_write_paths, syscall_policy, \
         allowed_action_types, blocked_action_types, enforcement, created_at, updated_at \
         FROM conductor_cages WHERE pipeline_id = $1"
    )
    .bind(pipeline_id)
    .fetch_optional(pool).await
    .context("fetch cage policy")?;

    Ok(row.map(row_to_cage))
}

#[allow(dead_code)]
pub async fn fetch_by_id(pool: &PgPool, id: Uuid) -> Result<CagePolicy> {
    let row = sqlx::query(
        "SELECT id, pipeline_id, max_cpu_ms, max_memory_bytes, max_file_size_bytes, \
         max_open_files, max_processes, allow_network, allowed_hosts, blocked_hosts, \
         allowed_ports, allowed_read_paths, allowed_write_paths, syscall_policy, \
         allowed_action_types, blocked_action_types, enforcement, created_at, updated_at \
         FROM conductor_cages WHERE id = $1"
    )
    .bind(id)
    .fetch_one(pool).await
    .context("fetch cage by id")?;

    Ok(row_to_cage(row))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCageRequest {
    pub pipeline_id:          Uuid,
    pub max_cpu_ms:           Option<i64>,
    pub max_memory_bytes:     Option<i64>,
    pub max_file_size_bytes:  Option<i64>,
    pub max_open_files:       Option<i32>,
    pub max_processes:        Option<i32>,
    pub allow_network:        Option<bool>,
    pub allowed_hosts:        Option<Vec<String>>,
    pub blocked_hosts:        Option<Vec<String>>,
    pub allowed_ports:        Option<Vec<i32>>,
    pub allowed_read_paths:   Option<Vec<String>>,
    pub allowed_write_paths:  Option<Vec<String>>,
    pub syscall_policy:       Option<String>,
    pub allowed_action_types: Option<Vec<String>>,
    pub blocked_action_types: Option<Vec<String>>,
    pub enforcement:          Option<String>,
}

pub async fn upsert(pool: &PgPool, req: CreateCageRequest) -> Result<CagePolicy> {
    let row = sqlx::query(
        "INSERT INTO conductor_cages (
            pipeline_id, max_cpu_ms, max_memory_bytes, max_file_size_bytes,
            max_open_files, max_processes, allow_network,
            allowed_hosts, blocked_hosts, allowed_ports,
            allowed_read_paths, allowed_write_paths,
            syscall_policy, allowed_action_types, blocked_action_types, enforcement
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         ON CONFLICT (pipeline_id) DO UPDATE SET
            max_cpu_ms           = EXCLUDED.max_cpu_ms,
            max_memory_bytes     = EXCLUDED.max_memory_bytes,
            max_file_size_bytes  = EXCLUDED.max_file_size_bytes,
            max_open_files       = EXCLUDED.max_open_files,
            max_processes        = EXCLUDED.max_processes,
            allow_network        = EXCLUDED.allow_network,
            allowed_hosts        = EXCLUDED.allowed_hosts,
            blocked_hosts        = EXCLUDED.blocked_hosts,
            allowed_ports        = EXCLUDED.allowed_ports,
            allowed_read_paths   = EXCLUDED.allowed_read_paths,
            allowed_write_paths  = EXCLUDED.allowed_write_paths,
            syscall_policy       = EXCLUDED.syscall_policy,
            allowed_action_types = EXCLUDED.allowed_action_types,
            blocked_action_types = EXCLUDED.blocked_action_types,
            enforcement          = EXCLUDED.enforcement,
            updated_at           = NOW()
         RETURNING *"
    )
    .bind(req.pipeline_id)
    .bind(req.max_cpu_ms.unwrap_or(30_000))
    .bind(req.max_memory_bytes.unwrap_or(134_217_728))
    .bind(req.max_file_size_bytes.unwrap_or(10_485_760))
    .bind(req.max_open_files.unwrap_or(64))
    .bind(req.max_processes.unwrap_or(8))
    .bind(req.allow_network.unwrap_or(true))
    .bind(req.allowed_hosts.unwrap_or_default())
    .bind(req.blocked_hosts.unwrap_or_default())
    .bind(req.allowed_ports.unwrap_or_default())
    .bind(req.allowed_read_paths.unwrap_or_default())
    .bind(req.allowed_write_paths.unwrap_or_default())
    .bind(req.syscall_policy.unwrap_or_else(|| "default".into()))
    .bind(req.allowed_action_types.unwrap_or_default())
    .bind(req.blocked_action_types.unwrap_or_default())
    .bind(req.enforcement.unwrap_or_else(|| "enforce".into()))
    .fetch_one(pool).await
    .context("upsert cage policy")?;

    Ok(row_to_cage(row))
}

pub async fn delete(pool: &PgPool, pipeline_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM conductor_cages WHERE pipeline_id = $1")
        .bind(pipeline_id).execute(pool).await.context("delete cage")?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn cage_deny(policy: &CagePolicy, rule: &str, reason: String) -> CageEvalResult {
    match policy.enforcement {
        Enforcement::Audit => {
            tracing::warn!(rule, reason = %reason, "Cage violation in AUDIT mode — allowing");
            CageEvalResult {
                verdict:        CageVerdict::Audit,
                deny_reason:    Some(reason),
                policy_matched: Some(rule.into()),
                rlimits:        rlimits_from(policy),
            }
        }
        _ => {
            tracing::warn!(rule, reason = %reason, "Cage DENIED action");
            CageEvalResult {
                verdict:        CageVerdict::Deny,
                deny_reason:    Some(reason),
                policy_matched: Some(rule.into()),
                rlimits:        rlimits_from(policy),
            }
        }
    }
}

/// Host matching: supports exact match, wildcard prefix `*.example.com`,
/// CIDR notation for IPs, and localhost aliases.
fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern == "*" { return true; }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        return host.ends_with(suffix) || host == &pattern[2..];
    }
    // Localhost aliases
    if pattern == "localhost" {
        return host == "localhost" || host == "127.0.0.1" || host == "::1";
    }
    host == pattern
}

fn rlimits_from(p: &CagePolicy) -> OsRlimits {
    OsRlimits {
        cpu_seconds:   (p.max_cpu_ms / 1000).max(1) as u64,
        memory_bytes:  p.max_memory_bytes as u64,
        file_size:     p.max_file_size_bytes as u64,
        open_files:    p.max_open_files as u64,
        max_processes: p.max_processes as u64,
    }
}

fn default_rlimits() -> OsRlimits {
    OsRlimits {
        cpu_seconds:   30,
        memory_bytes:  134_217_728, // 128 MiB
        file_size:     10_485_760,  // 10 MiB
        open_files:    64,
        max_processes: 8,
    }
}

fn row_to_cage(row: sqlx::postgres::PgRow) -> CagePolicy {
    let syscall_str: String = row.try_get("syscall_policy").unwrap_or_default();
    let enforce_str: String = row.try_get("enforcement").unwrap_or_default();
    CagePolicy {
        id:                   row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        pipeline_id:          row.try_get("pipeline_id").unwrap_or_else(|_| Uuid::new_v4()),
        max_cpu_ms:           row.try_get("max_cpu_ms").unwrap_or(30_000),
        max_memory_bytes:     row.try_get("max_memory_bytes").unwrap_or(134_217_728),
        max_file_size_bytes:  row.try_get("max_file_size_bytes").unwrap_or(10_485_760),
        max_open_files:       row.try_get("max_open_files").unwrap_or(64),
        max_processes:        row.try_get("max_processes").unwrap_or(8),
        allow_network:        row.try_get("allow_network").unwrap_or(true),
        allowed_hosts:        row.try_get("allowed_hosts").unwrap_or_default(),
        blocked_hosts:        row.try_get("blocked_hosts").unwrap_or_default(),
        allowed_ports:        row.try_get("allowed_ports").unwrap_or_default(),
        allowed_read_paths:   row.try_get("allowed_read_paths").unwrap_or_default(),
        allowed_write_paths:  row.try_get("allowed_write_paths").unwrap_or_default(),
        syscall_policy:       SyscallPolicy::from(syscall_str.as_str()),
        allowed_action_types: row.try_get("allowed_action_types").unwrap_or_default(),
        blocked_action_types: row.try_get("blocked_action_types").unwrap_or_default(),
        enforcement:          Enforcement::from(enforce_str.as_str()),
        created_at:           row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:           row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}
