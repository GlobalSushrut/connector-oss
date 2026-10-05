//! Spawn supervised children in their own process groups (Unix) so trees can be torn down cleanly.

use crate::log_fanin::LinePrefixWriter;
use crate::Backoff;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{stderr, stdout};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

/// Optional restart policy after a **non-zero exit code** (Phase 5.10.4). Signal exits are not retried.
#[derive(Debug, Clone)]
pub struct RestartOnCodeFailure {
    pub max_retries: u32,
    pub base: Duration,
    pub cap: Duration,
    /// When true, log retry sleeps to stderr (e.g. mirrors `CONNECTOR_SUPERVISOR_LOGS=1` for the node).
    pub log_retries: bool,
}

impl RestartOnCodeFailure {
    /// Reads `CONNECTOR_SUPERVISOR_RESTART_MAX` / `_BASE_MS` / `_CAP_MS` and `CONNECTOR_SUPERVISOR_LOGS`.
    /// `RESTART_MAX` unset or `0` → no restarts (`None`).
    pub fn from_node_supervisor_env() -> Option<Self> {
        let max_retries: u32 = std::env::var("CONNECTOR_SUPERVISOR_RESTART_MAX")
            .ok()?
            .trim()
            .parse()
            .ok()?;
        if max_retries == 0 {
            return None;
        }
        let max_retries = max_retries.min(50);
        let base_ms: u64 = std::env::var("CONNECTOR_SUPERVISOR_RESTART_BASE_MS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(1_000);
        let cap_ms: u64 = std::env::var("CONNECTOR_SUPERVISOR_RESTART_CAP_MS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(60_000);
        let base_ms = base_ms.clamp(1, 120_000);
        let cap_ms = cap_ms.clamp(base_ms, 300_000);
        let log_retries = std::env::var("CONNECTOR_SUPERVISOR_LOGS")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        Some(Self {
            max_retries,
            base: Duration::from_millis(base_ms),
            cap: Duration::from_millis(cap_ms),
            log_retries,
        })
    }
}

/// One child program to run under supervision.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// When true, inherit the parent process environment before applying [`Self::env`].
    pub inherit_parent_env: bool,
    /// Environment entries applied after optional inheritance (last wins on duplicate keys).
    pub env: Vec<(String, String)>,
    /// When true, pipe stdout/stderr and prefix lines for fan-in. When false, discard child output.
    pub forward_logs: bool,
    /// When set and the child exits with **non-success** (`ExitStatus::success() == false`), the
    /// supervisor POSTs `plugin-crash-recovery/record` to `CONNECTOR_API_URL` (Phase 5.10.2).
    /// Use a manifest-style id (`vendor/slug`). Ignored for successful exits.
    pub plugin_crash_plugin_id: Option<String>,
    /// When set, after a non-zero **exit code** respawn the same spec with exponential backoff.
    /// Ignored for signal-terminated children and for [`ProcessGroup::spawn_many`] / [`ProcessGroup::join_all`] alone;
    /// use [`run_process_spec_with_restart`].
    pub restart_on_code_failure: Option<RestartOnCodeFailure>,
}

/// A running child plus Unix process group id (negative `kill` target).
pub struct SpawnedProcess {
    pub name: String,
    pub child: Child,
    /// Process group id for `kill(-pgid, sig)` on Unix; `0` if unavailable.
    pub pgid: i32,
    pub plugin_crash_plugin_id: Option<String>,
}

/// Configuration for graceful teardown.
#[derive(Debug, Clone)]
pub struct ProcessGroupConfig {
    pub shutdown_grace: Duration,
}

impl Default for ProcessGroupConfig {
    fn default() -> Self {
        Self {
            shutdown_grace: Duration::from_secs(15),
        }
    }
}

/// One or more spawned processes.
pub struct ProcessGroup {
    pub procs: Vec<SpawnedProcess>,
    log_tasks: Vec<JoinHandle<std::io::Result<()>>>,
}

impl ProcessGroup {
    pub async fn spawn_many(specs: Vec<ProcessSpec>) -> std::io::Result<Self> {
        let mut procs = Vec::new();
        let mut log_tasks = Vec::new();

        for spec in specs {
            let mut cmd = Command::new(&spec.program);
            cmd.args(&spec.args);
            if let Some(cwd) = &spec.cwd {
                cmd.current_dir(cwd);
            }
            cmd.stdin(Stdio::null());
            if spec.forward_logs {
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
            } else {
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
            }

            if spec.inherit_parent_env {
                cmd.envs(std::env::vars());
            }
            for (k, v) in &spec.env {
                cmd.env(k, v);
            }

            #[cfg(unix)]
            {
                unsafe {
                    cmd.pre_exec(|| {
                        if libc::setpgid(0, 0) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        // OS-grade: seccomp / no_new_privs when env intent is set (DockLock cage).
                        connector_plugin_runtime::linux_hardening::apply_linux_hardening_env()?;
                        Ok(())
                    });
                }
            }

            let mut child = cmd.spawn()?;
            let pgid = child.id().map(|id| id as i32).unwrap_or(0);

            if let Some(plugin_id) = spec.plugin_crash_plugin_id.as_deref() {
                if pgid > 0 {
                    let cgroup = connector_plugin_runtime::linux_cgroup::cgroup_attach_detail_for_request(
                        plugin_id,
                        pgid as u32,
                        spec.cwd.as_deref(),
                    );
                    if cgroup.get("enforce").and_then(|v| v.as_bool()) == Some(true)
                        && cgroup.get("attached").and_then(|v| v.as_bool()) == Some(false)
                    {
                        let _ = child.start_kill();
                        let msg = cgroup
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("cgroup attach failed");
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
                    }
                }
            }

            let name = spec.name.clone();
            if spec.forward_logs {
                let child_stdout = child.stdout.take();
                let child_stderr = child.stderr.take();

                if let Some(out) = child_stdout {
                    let n = name.clone();
                    log_tasks.push(tokio::spawn(async move {
                        let w = LinePrefixWriter::new(stdout(), format!("[{}]", n));
                        w.copy_lines(out).await
                    }));
                }
                if let Some(err) = child_stderr {
                    let n = name.clone();
                    log_tasks.push(tokio::spawn(async move {
                        let w = LinePrefixWriter::new(stderr(), format!("[{}][err]", n));
                        w.copy_lines(err).await
                    }));
                }
            }

            procs.push(SpawnedProcess {
                name: spec.name,
                child,
                pgid,
                plugin_crash_plugin_id: spec.plugin_crash_plugin_id.clone(),
            });
        }

        Ok(Self { procs, log_tasks })
    }

    /// SIGTERM process groups (Unix), wait `grace`, then `SIGKILL` groups and `Child::kill` each handle.
    pub async fn shutdown_graceful(&mut self, cfg: &ProcessGroupConfig) {
        for sp in self.procs.iter() {
            #[cfg(unix)]
            if sp.pgid > 0 {
                unsafe {
                    libc::kill(-sp.pgid, libc::SIGTERM);
                }
            }
        }
        tokio::time::sleep(cfg.shutdown_grace).await;
        for sp in self.procs.iter_mut() {
            let _ = sp.child.kill();
            #[cfg(unix)]
            if sp.pgid > 0 {
                unsafe {
                    libc::kill(-sp.pgid, libc::SIGKILL);
                }
            }
        }
    }

    /// Wait for all children (log tasks finish when streams close).
    pub async fn join_all(mut self) -> std::io::Result<Vec<std::process::ExitStatus>> {
        let mut statuses = Vec::new();
        for mut sp in self.procs.drain(..) {
            let crash_id = sp.plugin_crash_plugin_id.clone();
            let st = sp.child.wait().await?;
            if let Some(ref pid) = crash_id {
                if !st.success() {
                    crate::kernel_crash_notify::notify_plugin_crash_on_exit(pid).await;
                }
            }
            statuses.push(st);
        }
        for t in self.log_tasks {
            let _ = t.await;
        }
        Ok(statuses)
    }
}

/// Spawn and supervise **one** [`ProcessSpec`] (use `spawn_many` for multi-child groups without this loop).
///
/// Calls `on_spawned(pid)` after each successful spawn; if it returns `false`, the current child is joined
/// and the function returns `Ok(None)`.
///
/// Returns `Ok(Some(status))` when the supervise loop ends: success exit, signal exit, or coded failure
/// with no retries left. Returns `Err` only for I/O failures from spawn/wait after retries are exhausted
/// (or when no PID is available on the final attempt).
pub async fn run_process_spec_with_restart<F>(spec: ProcessSpec, mut on_spawned: F) -> std::io::Result<Option<std::process::ExitStatus>>
where
    F: FnMut(u32) -> bool,
{
    let policy = spec.restart_on_code_failure.clone();
    let max_cycles = policy
        .as_ref()
        .map(|p| p.max_retries.saturating_add(1))
        .unwrap_or(1);
    let mut backoff = policy
        .as_ref()
        .map(|p| Backoff::new(p.base, p.cap));
    let log_retries = policy.as_ref().map(|p| p.log_retries).unwrap_or(false);
    let label = spec.name.clone();

    for cycle in 0..max_cycles {
        if cycle > 0 {
            if let Some(ref mut b) = backoff {
                let d = b.next_sleep();
                if log_retries {
                    eprintln!(
                        "[connector-supervisor:{}] restart {}/{} after {:?}",
                        label,
                        cycle,
                        max_cycles.saturating_sub(1),
                        d
                    );
                }
                tokio::time::sleep(d).await;
            }
        }

        let group = match ProcessGroup::spawn_many(vec![spec.clone()]).await {
            Ok(g) => g,
            Err(e) => {
                if cycle + 1 >= max_cycles {
                    return Err(e);
                }
                continue;
            }
        };

        let pid = match group.procs.first().and_then(|p| p.child.id()) {
            Some(p) => p,
            None => {
                let _ = group.join_all().await;
                if cycle + 1 >= max_cycles {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "spawned child has no PID",
                    ));
                }
                continue;
            }
        };

        if !on_spawned(pid) {
            let _ = group.join_all().await;
            return Ok(None);
        }

        let statuses = match group.join_all().await {
            Ok(s) => s,
            Err(e) => {
                if cycle + 1 >= max_cycles {
                    return Err(e);
                }
                continue;
            }
        };

        let Some(st) = statuses.into_iter().next() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "supervisor returned no exit status",
            ));
        };

        if st.success() {
            return Ok(Some(st));
        }
        if st.code().is_none() {
            return Ok(Some(st));
        }
        if cycle + 1 >= max_cycles {
            if log_retries {
                eprintln!(
                    "[connector-supervisor:{}] exited with code {:?} — retries exhausted",
                    label,
                    st.code()
                );
            }
            return Ok(Some(st));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "run_process_spec_with_restart: internal loop exhausted",
    ))
}

#[cfg(test)]
mod restart_tests {
    use super::*;

    #[tokio::test]
    async fn coded_failure_retries_then_returns_last_status() {
        let (program, args): (PathBuf, Vec<String>) = if cfg!(windows) {
            (
                PathBuf::from("cmd"),
                vec!["/C".into(), "exit 1".into()],
            )
        } else {
            (PathBuf::from("sh"), vec!["-c".into(), "exit 1".into()])
        };
        let st = run_process_spec_with_restart(
            ProcessSpec {
                name: "retry-test".into(),
                program,
                args,
                cwd: None,
                inherit_parent_env: false,
                env: vec![],
                forward_logs: false,
                plugin_crash_plugin_id: None,
                restart_on_code_failure: Some(RestartOnCodeFailure {
                    max_retries: 2,
                    base: Duration::from_millis(1),
                    cap: Duration::from_millis(10),
                    log_retries: false,
                }),
            },
            |_| true,
        )
        .await
        .expect("run")
        .expect("some status");
        assert!(!st.success());
        assert_eq!(st.code(), Some(1));
    }
}
