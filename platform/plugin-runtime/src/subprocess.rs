use std::process::Stdio;

use async_trait::async_trait;
use serde_json::json;

use crate::error::PluginRuntimeError;
use crate::types::{IsolationRuntime, SpawnReceipt, SpawnRequest};
use crate::PluginIsolationBackend;

#[derive(Debug, Default, Clone)]
pub struct SubprocessPluginBackend;

/// Fire-and-forget subprocess with its own process group (Unix).
pub async fn spawn_detached(req: SpawnRequest) -> Result<u32, PluginRuntimeError> {
    let mut cmd = tokio::process::Command::new(&req.program);
    cmd.args(&req.args);
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    for (k, v) in &req.env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    {
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                crate::linux_hardening::apply_linux_hardening_env()?;
                Ok(())
            });
        }
    }
    let child = cmd.spawn()?;
    Ok(child.id().unwrap_or(0))
}

#[async_trait]
impl PluginIsolationBackend for SubprocessPluginBackend {
    fn kind(&self) -> IsolationRuntime {
        IsolationRuntime::Subprocess
    }

    async fn spawn(&self, req: SpawnRequest) -> Result<SpawnReceipt, PluginRuntimeError> {
        let mut req = req;
        if crate::productionish_env() {
            if !req.egress_allowlist.is_empty() {
                return Err(PluginRuntimeError::Spawn(
                    "subprocess_cannot_enforce_egress_allowlist — use docker_lab or microvm for destination allowlists".into(),
                ));
            }
            let has_intent = req.env.iter().any(|(k, _)| {
                k == "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT"
                    || k == "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP"
            });
            if !has_intent {
                req.env.push((
                    "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT".into(),
                    "no_network".into(),
                ));
            }
        }
        let workspace_quota = crate::subprocess_disk::preflight_workspace_quota(&req)?;
        let pid = spawn_detached(req.clone()).await?;
        let cgroup = crate::linux_cgroup::cgroup_attach_detail_for_request(
            &req.plugin_id,
            pid,
            req.workspace_host_mount.as_deref().or(req.cwd.as_deref()),
        );
        if cgroup.get("enforce").and_then(|v| v.as_bool()) == Some(true)
            && cgroup.get("attached").and_then(|v| v.as_bool()) == Some(false)
        {
            let msg = cgroup
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("cgroup attach failed");
            return Err(PluginRuntimeError::Spawn(msg.into()));
        }
        Ok(SpawnReceipt {
            backend: "subprocess".into(),
            plugin_id: req.plugin_id,
            detail: json!({
                "pid": pid,
                "phase": "5.1",
                "egress_allowlist_len": req.egress_allowlist.len(),
                "cgroup": cgroup,
                "workspace_quota": workspace_quota,
                "note": "Detached child process. Production: empty allowlist + seccomp no_network (host subprocess cannot pin destinations). Destination allowlists require docker_lab or microVM iptables. Linux: cgroup v2 attach with default memory/cpu/pids when parent is writable; production-ish fails spawn if attach is required and fails."
            }),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn detached_spawn_returns_pid() {
        let req = SpawnRequest {
            plugin_id: "demo/t".into(),
            program: PathBuf::from("/bin/true"),
            args: vec![],
            cwd: None,
            env: vec![],
            egress_allowlist: vec![],
            workspace_host_mount: None,
            docker_run_detached: true,
        };
        let pid = spawn_detached(req).await.expect("spawn");
        assert!(pid > 0);
    }
}
