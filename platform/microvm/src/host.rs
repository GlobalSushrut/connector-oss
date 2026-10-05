use std::path::{Path, PathBuf};

use serde_json::json;

use crate::error::MicrovmError;
use crate::model::FirecrackerVmConfig;

/// Host-side microVM manager using Firecracker UDS API on Unix.
#[derive(Debug, Clone, Default)]
pub struct MicrovmHost {
    pub api_socket_path: Option<PathBuf>,
    pub firecracker_bin: Option<PathBuf>,
    pub jailer_bin: Option<PathBuf>,
}

impl MicrovmHost {
    pub fn new(api_socket_path: Option<PathBuf>) -> Self {
        Self {
            api_socket_path,
            firecracker_bin: None,
            jailer_bin: None,
        }
    }

    pub fn with_firecracker_bin(mut self, firecracker_bin: Option<PathBuf>) -> Self {
        self.firecracker_bin = firecracker_bin;
        self
    }

    pub fn with_jailer_bin(mut self, jailer_bin: Option<PathBuf>) -> Self {
        self.jailer_bin = jailer_bin;
        self
    }

    pub fn is_ready(&self) -> bool {
        self.resolve_firecracker_bin().is_some()
    }

    pub fn ensure_slot(&self, vm_id: &str) -> Result<serde_json::Value, MicrovmError> {
        if vm_id.trim().is_empty() {
            return Err(MicrovmError::InvalidConfig("vm_id required".into()));
        }
        if !self.is_ready() {
            return Err(MicrovmError::HostNotConfigured(
                "firecracker binary not configured or missing".into(),
            ));
        }
        Ok(json!({
            "ok": true,
            "vm_id": vm_id,
            "slot_ready": true
        }))
    }

    pub fn start(&self, cfg: &FirecrackerVmConfig) -> Result<serde_json::Value, MicrovmError> {
        self.start_with_options(cfg, false)
    }

    /// Start Firecracker; when `use_jailer` is true, wrap via jailer (harden path).
    pub fn start_with_options(
        &self,
        cfg: &FirecrackerVmConfig,
        use_jailer: bool,
    ) -> Result<serde_json::Value, MicrovmError> {
        if cfg.vm_id.trim().is_empty() {
            return Err(MicrovmError::InvalidConfig("vm_id required".into()));
        }
        if cfg.api_socket_path.trim().is_empty() {
            return Err(MicrovmError::InvalidConfig("api_socket_path required".into()));
        }
        if cfg.boot_source.kernel_image_path.trim().is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "boot_source.kernel_image_path required".into(),
            ));
        }
        if !Path::new(&cfg.boot_source.kernel_image_path).is_file() {
            return Err(MicrovmError::InvalidConfig(format!(
                "kernel image not found: {}",
                cfg.boot_source.kernel_image_path
            )));
        }
        let root_drive = cfg.drives.iter().find(|d| d.is_root_device);
        if root_drive.is_none() {
            return Err(MicrovmError::InvalidConfig(
                "at least one root drive is required".into(),
            ));
        }
        if let Some(d) = root_drive {
            if !Path::new(&d.path_on_host).is_file() {
                return Err(MicrovmError::InvalidConfig(format!(
                    "root drive not found: {}",
                    d.path_on_host
                )));
            }
        }
        #[cfg(unix)]
        {
            self.start_unix(cfg, use_jailer)
        }
        #[cfg(not(unix))]
        {
            let _ = use_jailer;
            Err(MicrovmError::UnsupportedHost(
                "firecracker host lifecycle currently requires unix sockets".into(),
            ))
        }
    }

    /// Pause guest vCPUs via Firecracker `PATCH /vm` state=Paused.
    /// v1.9 rejects `PUT /vm`.
    pub fn pause(&self, api_socket_path: &str) -> Result<serde_json::Value, MicrovmError> {
        #[cfg(unix)]
        {
            self.api_patch(api_socket_path, "/vm", &json!({ "state": "Paused" }))?;
            Ok(json!({"ok": true, "state": "Paused", "api_socket_path": api_socket_path}))
        }
        #[cfg(not(unix))]
        {
            let _ = api_socket_path;
            Err(MicrovmError::UnsupportedHost("pause requires unix".into()))
        }
    }

    /// Resume guest vCPUs.
    pub fn resume(&self, api_socket_path: &str) -> Result<serde_json::Value, MicrovmError> {
        #[cfg(unix)]
        {
            self.api_patch(api_socket_path, "/vm", &json!({ "state": "Resumed" }))?;
            Ok(json!({"ok": true, "state": "Resumed", "api_socket_path": api_socket_path}))
        }
        #[cfg(not(unix))]
        {
            let _ = api_socket_path;
            Err(MicrovmError::UnsupportedHost("resume requires unix".into()))
        }
    }

    /// Graceful stop attempt then force-kill by pid.
    pub fn stop(
        &self,
        api_socket_path: &str,
        pid: Option<u32>,
    ) -> Result<serde_json::Value, MicrovmError> {
        #[cfg(unix)]
        {
            let mut api_ok = false;
            if Path::new(api_socket_path).exists() {
                if self
                    .api_put(
                        api_socket_path,
                        "/actions",
                        &json!({ "action_type": "SendCtrlAltDel" }),
                    )
                    .is_ok()
                {
                    api_ok = true;
                    std::thread::sleep(std::time::Duration::from_millis(400));
                }
            }
            let mut killed = false;
            if let Some(p) = pid {
                unsafe {
                    let _ = libc::kill(p as i32, libc::SIGTERM);
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let _ = libc::kill(p as i32, libc::SIGKILL);
                    killed = true;
                }
            }
            let _ = std::fs::remove_file(api_socket_path);
            Ok(json!({
                "ok": true,
                "api_signal": api_ok,
                "killed": killed,
                "pid": pid,
            }))
        }
        #[cfg(not(unix))]
        {
            let _ = (api_socket_path, pid);
            Err(MicrovmError::UnsupportedHost("stop requires unix".into()))
        }
    }

    fn resolve_firecracker_bin(&self) -> Option<PathBuf> {
        if let Some(p) = &self.firecracker_bin {
            if p.is_file() {
                return Some(p.clone());
            }
        }
        if let Ok(p) = std::env::var("CONNECTOR_FIRECRACKER_BIN") {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
        if let Some(p) = option_env!("CONNECTOR_VENDORED_FIRECRACKER_PATH") {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
        None
    }

    fn resolve_jailer_bin(&self) -> Option<PathBuf> {
        if let Some(p) = &self.jailer_bin {
            if p.is_file() {
                return Some(p.clone());
            }
        }
        if let Ok(p) = std::env::var("CONNECTOR_JAILER_BIN") {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
        None
    }
}

#[cfg(unix)]
impl MicrovmHost {
    fn api_put(
        &self,
        api_socket_path: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(), MicrovmError> {
        self.api_method("PUT", api_socket_path, path, body)
    }

    fn api_patch(
        &self,
        api_socket_path: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(), MicrovmError> {
        self.api_method("PATCH", api_socket_path, path, body)
    }

    fn api_method(
        &self,
        method: &str,
        api_socket_path: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(), MicrovmError> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        for _ in 0..25 {
            if Path::new(api_socket_path).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut last_err = String::new();
        for attempt in 0..8 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(40 * attempt as u64));
            }
            let mut stream = match UnixStream::connect(api_socket_path) {
                Ok(s) => s,
                Err(e) => {
                    last_err = format!("connect {api_socket_path}: {e}");
                    continue;
                }
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            let payload = serde_json::to_vec(body).map_err(|e| MicrovmError::Api(e.to_string()))?;
            // Firecracker keeps connections alive — do not require EOF to finish the response.
            let req = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                payload.len()
            );
            if let Err(e) = stream
                .write_all(req.as_bytes())
                .and_then(|_| stream.write_all(&payload))
                .and_then(|_| stream.flush())
            {
                last_err = format!("write {path}: {e}");
                continue;
            }
            // Read until end of headers (\r\n\r\n). 204 has no body.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n")
                            || buf.windows(2).any(|w| w == b"\n\n")
                        {
                            break;
                        }
                        if buf.len() > 16_384 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            let resp = String::from_utf8_lossy(&buf);
            if resp.contains("HTTP/1.1 204")
                || resp.contains("HTTP/1.0 204")
                || resp.contains("HTTP/1.1 200")
                || resp.contains("HTTP/1.0 200")
            {
                return Ok(());
            }
            last_err = format!("PUT {path} failed: {resp}");
        }
        Err(MicrovmError::Api(last_err))
    }

    fn start_unix(
        &self,
        cfg: &FirecrackerVmConfig,
        use_jailer: bool,
    ) -> Result<serde_json::Value, MicrovmError> {
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        let firecracker_bin = self.resolve_firecracker_bin().ok_or_else(|| {
            MicrovmError::HostNotConfigured("set CONNECTOR_FIRECRACKER_BIN or vendored path".into())
        })?;
        let socket_path = PathBuf::from(&cfg.api_socket_path);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| MicrovmError::Io(e.to_string()))?;
        }
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }
        if let Some(parent) = Path::new(&cfg.log_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.log_path)
            .map_err(|e| MicrovmError::Io(format!("open {}: {}", cfg.log_path, e)))?;

        let mut jailed = false;
        let child = if use_jailer {
            let jailer = self.resolve_jailer_bin().ok_or_else(|| {
                MicrovmError::HostNotConfigured(
                    "jailer required but CONNECTOR_JAILER_BIN missing".into(),
                )
            })?;
            let chroot_base = std::env::var("CONNECTOR_JAILER_CHROOT_BASE")
                .unwrap_or_else(|_| "/var/lib/connector/microvm/jailer".into());
            std::fs::create_dir_all(&chroot_base).map_err(|e| MicrovmError::Io(e.to_string()))?;
            let uid = std::env::var("CONNECTOR_JAILER_UID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(65534);
            let gid = std::env::var("CONNECTOR_JAILER_GID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(65534);
            let mut cmd = Command::new(&jailer);
            cmd.arg("--id")
                .arg(&cfg.vm_id)
                .arg("--exec-file")
                .arg(&firecracker_bin)
                .arg("--uid")
                .arg(uid.to_string())
                .arg("--gid")
                .arg(gid.to_string())
                .arg("--chroot-base-dir")
                .arg(&chroot_base)
                .arg("--")
                .arg("--api-sock")
                .arg(&cfg.api_socket_path)
                .stdout(Stdio::from(
                    log_file
                        .try_clone()
                        .map_err(|e| MicrovmError::Io(e.to_string()))?,
                ))
                .stderr(Stdio::from(log_file));
            jailed = true;
            cmd.spawn().map_err(|e| {
                MicrovmError::Process(format!("spawn jailer {}: {e}", jailer.display()))
            })?
        } else {
            let mut cmd = Command::new(&firecracker_bin);
            cmd.arg("--api-sock")
                .arg(&cfg.api_socket_path)
                .stdout(Stdio::from(
                    log_file
                        .try_clone()
                        .map_err(|e| MicrovmError::Io(e.to_string()))?,
                ))
                .stderr(Stdio::from(log_file));
            cmd.spawn().map_err(|e| {
                MicrovmError::Process(format!("spawn {}: {e}", firecracker_bin.display()))
            })?
        };

        let pid = child.id();
        // Detach: keep Firecracker running after this function returns.
        std::mem::forget(child);

        let started_at = Instant::now();
        let timeout = Duration::from_secs(8);
        while !socket_path.exists() {
            if started_at.elapsed() > timeout {
                return Err(MicrovmError::Process(format!(
                    "firecracker did not create api socket {} in time",
                    cfg.api_socket_path
                )));
            }
            thread::sleep(Duration::from_millis(40));
        }

        self.api_put(
            &cfg.api_socket_path,
            "/machine-config",
            &json!({
                "vcpu_count": cfg.machine_config.vcpu_count,
                "mem_size_mib": cfg.machine_config.mem_mib,
                "smt": cfg.machine_config.smt,
            }),
        )?;
        let mut boot = json!({
            "kernel_image_path": cfg.boot_source.kernel_image_path,
        });
        if let Some(args) = &cfg.boot_source.boot_args {
            boot["boot_args"] = json!(args);
        }
        if let Some(initrd) = &cfg.boot_source.initrd_path {
            boot["initrd_path"] = json!(initrd);
        }
        self.api_put(&cfg.api_socket_path, "/boot-source", &boot)?;
        for d in &cfg.drives {
            let p = format!("/drives/{}", d.drive_id);
            self.api_put(
                &cfg.api_socket_path,
                &p,
                &json!({
                    "drive_id": d.drive_id,
                    "path_on_host": d.path_on_host,
                    "is_root_device": d.is_root_device,
                    "is_read_only": d.is_read_only,
                }),
            )?;
        }
        if let Some(net) = &cfg.network_iface {
            let p = format!("/network-interfaces/{}", net.iface_id);
            self.api_put(
                &cfg.api_socket_path,
                &p,
                &json!({
                    "iface_id": net.iface_id,
                    "host_dev_name": net.host_dev_name,
                }),
            )?;
        }
        if let Some(vsock) = &cfg.vsock {
            self.api_put(
                &cfg.api_socket_path,
                "/vsock",
                &json!({
                    "guest_cid": vsock.guest_cid,
                    "uds_path": vsock.uds_path,
                }),
            )?;
        }
        if let Some(metrics_path) = &cfg.metrics_path {
            self.api_put(
                &cfg.api_socket_path,
                "/metrics",
                &json!({ "metrics_path": metrics_path }),
            )?;
        }
        self.api_put(
            &cfg.api_socket_path,
            "/actions",
            &json!({ "action_type": "InstanceStart" }),
        )?;

        Ok(json!({
            "ok": true,
            "vm_id": cfg.vm_id,
            "pid": pid,
            "api_socket_path": cfg.api_socket_path,
            "log_path": cfg.log_path,
            "firecracker_bin": firecracker_bin.display().to_string(),
            "jailed": jailed,
        }))
    }
}
